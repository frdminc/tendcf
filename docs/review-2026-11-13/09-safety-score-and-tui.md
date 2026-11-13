# 09: G4 safety review, score and TUI

Base commit: eefea3c

How this was produced: one researching agent (Claude Opus), then an
independent checking agent that fetched the cited sources and tried to refute
each claim; nothing was executed.

Items by Weight after corrections: blocks-goal 4, misleads 4, improves 4,
nit 0 (12 response items; none withdrawn).

Reviewer: phase-2 seat 09 (Opus 5.5, high). The tendcf goal-review worktree
at `eefea3c`. Read-only. No repo file changed. Today 2026-11-13.

Sources consulted: map §2, §6, §9–§13, §16
(`docs/architecture/architecture-DEFINITIVE-v3.md`), the validator proposal
§0–§3, §8–§14 (`docs/architecture/tendcf-validate-proposal-2026-11-03.md`),
guide Q10 (`docs/paper/tendcf-architecture-guide.md:1566-1579`),
`schema/goal-file.schema.json`, `schema/approval-record.schema.json`, the
review README and goal definition, the phase-1 digest; 17 papers and 14 project
READMEs/LICENCEs listed under "Sources".

Tool note: `firecrawl_research_search_papers` returned 404 twice. Every other
firecrawl tool worked, so this is one tool failing, not firecrawl. Papers were
reached through the arXiv export API via `firecrawl_scrape`.

## Summary

1. G4 is not yet met by any design. Map §9 gives an exact, device-computed
   structural diff and a refusal path (accept, reject, withdraw; timeout is
   deny). That covers "exact, mechanically checked, can see and refuse". There
   is no scan, no score, no graded highlighting and no TUI. The first
   validator build has no diff at all: "'Approved' means 'adopted by root on
   the host'" (VAL:869-871; independently checked 2026-11-13: confirmed).
2. **Score: a capped checklist score, not a probability.** A deterministic
   rule layer over goal-file key paths sets per-hunk severity and hard caps.
   Two AI reviewers from different families can only subtract. They never lift
   a cap, a ceremony class or a refusal, and never authorize. G4 asks for a
   safety confidence out of 100%. The reviewer's proposal, for the operator's
   ruling and not a correction, is to show "NN/100" in bands, meaning "how much
   of this change passed named checks, weighted by what breaks if it is wrong",
   until a calibration corpus can back a "%" (X-safety-10; independently
   checked 2026-11-13: confirmed as a question for the operator).
3. **TUI: Textual** (MIT, Python 3.9+, the same language as `tendcf-validate`
   and the compiler; a terminal app, so it should run over SSH, and an old
   Textual discussion reports it working in Termux; neither is tested here).
   Borrow Toad's permission and diff screens and `textual-diff-view` (both last
   pushed in May 2026). Both are AGPL-3.0, so
   this needs the operator's licence ruling. **Runner-up:** Textual with
   MIT-only borrowing (Rich, lazygit/gitui interaction patterns). Mosaic
   (Kotlin, Apache-2.0, experimental) is the option if a Kotlin TUI is ever
   wanted (independently checked 2026-11-13: weakened, corrected).
4. **One "review document"** (hunks, findings, score, band, template strings)
   is produced once, hashed into `briefing_sha256`, and rendered by dumb CLI,
   TUI and Android renderers held to golden fixtures. The CLI, TUI, Termux and
   native-phone views then cannot disagree about what was shown.
5. The evidence says AI scanning is a weak, attackable second opinion. One
   stress test of an agent harness's permission classifier found an 81.0%
   end-to-end false-negative rate. Part of that came from actions the
   classifier never saw: 36.8% of the risky actions never reached it. On the
   in-scope actions it did evaluate, it missed 70.3% and wrongly flagged 31.9%
   (arXiv 2604.04978). LLM judges can be steered by injected text
   (arXiv 2403.17710). Explanations raise acceptance whether or not the AI is
   right (arXiv 2006.14779). That is why the AI is subtract-only here (independently checked 2026-11-13: weakened, corrected).

## Q1. Non-AI scanning, and a rule set for a goal-file diff

What exists. Each tool is one example of a layer:

| Layer | Example | What it says | Fit for tendcf |
|---|---|---|---|
| Preview of effects | Ansible check and diff mode | Check mode is "just a simulation"; modules without check support "report nothing and do nothing"; diff mode shows before and after ([rst, fetched](https://raw.githubusercontent.com/ansible/ansible-documentation/devel/docs/docsite/rst/playbook_guide/playbooks_checkmode.rst)) | Same shape as `cf-agent --simulate-json` (VAL:103, `cf-agent/cf-agent.c:189`): a preview, never the authority. Also the §9.10 activation gap. |
| Plan diff | Terraform plan JSON, `nixos-rebuild dry-activate`, nvd and nix-diff | Machine-readable planned changes | Not fetched. Described from knowledge. tendcf's structural diff (§9.2) already plays this role. |
| Policy-as-code over the plan | OPA/conftest, Checkov, KICS, Trivy, tfsec, Semgrep | Rules as data over a structured plan | Not fetched. The pattern to copy: rules as data, each with an id, a severity and a remediation. |
| Nix linters | statix | Lints antipatterns; works on the AST and "does not evaluate any nix code" ([README](https://raw.githubusercontent.com/oppiliappan/statix/master/README.md), fetched 2026-11-13) | A style linter, not a safety linter. Useful at authoring, not at consent. deadnix and vulnix: not fetched. |

What the research says about IaC scanners. Rules over-approximate, and a
filtering layer recovers precision: IntelliSA reports F1 83% (arXiv 2601.14595,
MSR 2026; independently checked 2026-11-13: confirmed). An LLM-written fix can
satisfy the scanner without fixing anything: 71.4% of plan-compared Terraform
repairs were "deceptive fixes that pass automated checks while leaving the
underlying vulnerability in place" (TerraProbe, arXiv 2606.26590, 2026-06-25;
independently checked 2026-11-13: weakened, corrected). Lesson: **the rule layer must work on the goal
file's meaning, the key paths and values, not on whether a scanner's finding
went away.**

**A rule set for a goal-file diff.** Rules are data in
`schema/review-rules.json`, a proposed new file. Each rule has `id`,
`match` (a key-path glob plus a transition: added, removed, changed,
present→absent, or value predicate), `severity_if_wrong` (one of `lockout`,
`privilege`, `management`, `data-loss`, `reversible`), `tier` and a
`template` explanation string. First set, keyed to v5 kinds as found in
`schema/goal-file.schema.json` at `eefea3c`:

| Rule | Match | If wrong |
|---|---|---|
| R-trust-1 | any `device-trust/*` hunk, or `schema_version` change | management (and already privileged, map §9.8) |
| R-trust-2 | `device-trust/trust-policy/*` `tier` or `local_yes_required` loosened | management |
| R-trust-3 | `device-trust/advisor-key/*` added, removed or changed | management |
| R-trust-4 | `device-trust/agent` or `policy-tree` sha256 changed | management |
| R-cov-1 | coverage leaves `comprehensive`, or entry becomes `deliberately-unmanaged` | management (§9.7) |
| R-del-1 | bare deletion of a managed entry (stops being managed, thing remains) | reversible, but tier "caution": owner may think it is removed |
| R-del-2 | tombstone (`present → absent`) | data-loss when the kind holds data, else reversible |
| R-del-3 | tombstone dropped from the file | management (silent un-management) |
| R-ilk-1 | `interlock/*` removed, or `blocks` narrowed | privilege (a guard removed) |
| R-ilk-2 | `interlock/*/pre_action.command` changed | privilege |
| R-svc-1 | `service/*/command` or `env` changed | privilege |
| R-svc-2 | `service/*/run_as` becomes root, or is unset on a root supervisor | privilege |
| R-svc-3 | `service/*/unit` supervisor flavour changed | reversible |
| R-uw-1 | `unit-writer/*` or `unit-package/*` changed | privilege |
| later | sshd, firewall, sudoers, boot, users, disk, package removal, network reachability of the update path | lockout |

Two design rules: an **uncovered kind** (no rule matches a hunk's kind) is
itself a finding and caps the score (below), so a new kind cannot arrive
unseen. **A hunk's tier comes only from rules**, never from AI text.

## Q2. AI scanning: accuracy, false reassurance, injection

Findings (each source fetched unless marked):

1. **Coverage boundary.** A stress test of an LLM permission classifier
   for an agent harness found an 81.0% end-to-end false-negative rate
   (95% CI 73.8–87.4). The vendor reported 17% on production traffic. 36.8% of
   risky actions fell outside the classifier's scope altogether
   ([arXiv 2604.04978](https://arxiv.org/abs/2604.04978), v3 2026-10-22); on
   in-scope actions the false-negative rate was 70.3% and the false-positive
   rate 31.9%. The authors call this "a fundamentally different workload" from
   the vendor's figure, not a contradiction. The classifier gates tool calls
   from a transcript; it is not a diff reviewer.
   Lesson for tendcf: say what the AI was shown. A scan over the goal-file diff
   says nothing about effects (§9.10, TC-23) (independently checked 2026-11-13:
   confirmed; the in-scope figures were added from the checker's reading).
2. **Fragile verdicts.** Renaming function or variable names, or adding
   library functions, flipped 26% (PaLM2) and 17% (GPT-4) of vulnerability
   verdicts ([SecLLMHolmes, arXiv 2312.12575](https://arxiv.org/abs/2312.12575),
   IEEE S&P 2024; independently checked 2026-11-13: weakened, corrected).
3. **Injection against judges.** JudgeDeceiver makes an LLM judge pick the
   attacker's candidate; known-answer and perplexity defences were
   insufficient ([arXiv 2403.17710](https://arxiv.org/abs/2403.17710), CCS 2024,
   v5 2025-08-24). Indirect injection through retrieved data:
   [arXiv 2302.12173](https://arxiv.org/abs/2302.12173) (2023). Code review is
   one of the attacked scenarios; simple injections beat defences in long
   context ([LongPIBench, arXiv 2608.28411](https://arxiv.org/abs/2608.28411),
   2026-08-28). A goal file carries attacker-choosable strings (`command`,
   `env`, ids, `report`), so **the diff is hostile input to the AI scanner.**
   JudgeDeceiver optimises its injection with gradients against open models in
   a pairwise "pick the best response" setting. How far it transfers to a
   closed model scoring one diff is not measured; plain injection (2302.12173,
   2608.28411) needs no such access (independently checked 2026-11-13:
   confirmed; transfer note added).
4. **Self-review is biased.** LLM evaluators recognise and favour their own
   generations (Panickssery et al.,
   [arXiv 2404.13076](https://arxiv.org/abs/2404.13076)). Separately,
   open-weight models are up to 26% more confident in an answer framed as their
   own chat turn than in the same answer given as user input
   ([arXiv 2606.03437](https://arxiv.org/abs/2606.03437), ACL 2026 Findings).
   The authoring AI (R13) should not score its own change. The 2404.13076
   citation was not fetched by the checker, so fetch it before merging
   (independently checked 2026-11-13: weakened, corrected).
5. **False reassurance.** Explanations increased acceptance of AI advice
   "regardless of its correctness"
   ([Bansal et al., arXiv 2006.14779](https://arxiv.org/abs/2006.14779), CHI'21).
   A displayed confidence helps calibrate trust but is not sufficient
   ([arXiv 2001.02114](https://arxiv.org/abs/2001.02114), FAT* 2020;
   independently checked 2026-11-13: confirmed).
   Automation-bias review: Goddard et al. 2012 (pubmed 21685142, snippet only).

Posture that follows:

1. The AI sees only the canonical diff rendered as data, with string values
   quoted and length-capped, and none of the author's prose (DC-3).
2. Its output is parsed into structured findings. A finding counts only if it
   cites a key path present in the diff. Free text is shown labelled
   "untrusted".
3. It may subtract and add findings; it may never remove a rule finding,
   raise a tier, lift a cap or change `ceremony_class`.
4. Two families where quota allows. Disagreement is itself a cap.
5. The AI scanner runs through the owner's advisor slot (§11, D39), so tendcf
   never runs their model. tendcf ships the default scan prompt as a public
   file, as §11 already does for the advisor prompt.

## Q3. Calibration, and the recommended score

Literature:

1. Verbalised LLM confidence is overconfident. Sampling consistency and
   aggregation help, and failure prediction stays weak on professional-knowledge
   tasks such as law. Across five datasets, white-box methods beat black-box
   ones only modestly (average AUROC 0.605 against 0.522)
   ([arXiv 2306.13063](https://arxiv.org/abs/2306.13063), ICLR 2024, v2 2024-03-17;
   independently checked 2026-11-13: weakened, corrected).
2. For RLHF models, verbalised confidence beats token probabilities, with
   about 50% relative ECE reduction
   ([arXiv 2305.14975](https://arxiv.org/abs/2305.14975), EMNLP 2023;
   independently checked 2026-11-13: confirmed).
3. P(True) is well calibrated "in the right format"; P(IK) partially
   generalises across tasks but is poorly calibrated on new ones
   ([arXiv 2207.05221](https://arxiv.org/abs/2207.05221), 2022; independently
   checked 2026-11-13: weakened, corrected).
4. Conformal methods give coverage guarantees only under exchangeability, which
   a hostile author breaks
   ([arXiv 2306.10193](https://arxiv.org/abs/2306.10193), ICLR 2024;
   [arXiv 2305.18404](https://arxiv.org/abs/2305.18404), 2023; independently
   checked 2026-11-13: confirmed).

Conclusion: no off-the-shelf method turns an LLM's opinion of a
config diff into a trustworthy probability, and an adversary controls the input
distribution. So **the number must be defined by rules, with AI able only to
lower it.**

**Recommended design: capped checklist score.** The 95 ceiling and the
"NN/100" wording below are options for the operator's ruling (X-safety-10);
G4 as agreed says "out of 100%".

```
base     = 95                      # proposed: never 100 (operator's ruling)
penalty  = sum over findings of weight[severity_if_wrong]
           lockout 60, privilege 50, management 45, data-loss 40,
           reversible 10, notice 3
ai_sub   = per AI reviewer, up to 30, only for findings citing a key path
score    = base - penalty - ai_sub, floored at 0
caps     = min of the caps that apply:
           any lockout/privilege/management finding    -> 40
           a check did not run or failed (rules, schema,
             simulate preview, an AI reviewer unavailable) -> 60
           a hunk whose kind no rule covers            -> 70
           the two AI families disagree on a tier      -> 70
           a touched domain is not comprehensive        -> 80
score    = min(score, caps)
band     = 0-39 danger, 40-69 caution, 70-89 notice, 90-95 plain
```

The weights are starting values, not measured; the bands and caps are the
load-bearing part.

**What the number means**, as the screen would say it under the "NN/100"
option: "**NN/100: how much of
this change passed tendcf's named checks, weighted by what goes wrong if it is
wrong. It is not the chance this change is safe.**" A second axis is always
shown: "**If this is wrong:** you could be locked out / something gains root /
tendcf stops managing this / data is deleted / easily undone."

**Explanation** = the list of checks, each with its points and the hunk it
fired on, all from rule templates. AI findings go in a separate box, "AI
reviewer (model, family) — untrusted", phrased in first person with
uncertainty. First-person uncertainty reduced over-reliance
([Kim et al., arXiv 2405.00623](https://arxiv.org/abs/2405.00623),
FAccT 2024, N=404).

**Path to "%":** collect a labelled corpus. Sources are real releases, the
fleet's own history and seeded red-team diffs; their labels are "an owner
would want to refuse". Fit isotonic regression from score to refusal rate,
publish a reliability figure, and re-fit per rule-set version. Only then show
"%". Whether "out of 100%" in G4 is shown as "/100" until then is the
operator's ruling (X-safety-10); it is not settled here.

## Q4. Warnings for non-experts; stopping reflex approval

Evidence:

1. Warning design moves behaviour. Over 25 million impressions, click-through
   was about 1 in 10 for Firefox malware warnings and 70.2% for Chrome SSL
   ([Akhawe and Felt, USENIX Security 2013](https://www.usenix.org/conference/usenixsecurity13/technical-sessions/presentation/akhawe)).
2. Comprehension was hard to improve, but opinionated design made "nearly 30%
   more total users" choose safety
   ([Felt et al., CHI 2015](https://research.google.com/pubs/archive/43265.pdf)).
3. Habituation is real and polymorphic warnings slow it. Snippet only:
   Anderson et al., CHI 2015 (fMRI); Anderson et al., CHI 2017 (workweek);
   Vance et al., MISQ 2018. All dl.acm.org, which firecrawl could not fetch.
4. In tendcf's own register, "big-diff rubber-stamping is TC-09 reborn" (residue R5,
   `docs/architecture/e1-adjudication-xhigh-2026-08-15.md:478`),
   and Q10 asks whether a diff is consentable at all (map:1281;
   guide:1566-1579).

Design:

1. **Four tiers per hunk:** plain, notice, caution, danger. Each is encoded
   three ways: a gutter glyph (` `, `·`, `!`, `‼`), a word (`NOTICE`,
   `CAUTION`, `DANGER`) and a colour-blind-safe colour (blue and orange, never
   red/green alone).
2. **"More dramatic" means more friction, not more noise.**
   1. notice: shown.
   2. caution: never collapsed, and each must be visited.
   3. danger: a per-hunk acknowledgement, then a polymorphic confirmation
      (type the affected service or key name shown, which changes each time).
   4. No blinking, no sound, no "approve all" at caution or above.
3. **Defaults:** focus starts on Refuse; Enter alone never approves; timeout
   is deny (§11 already); a diff over N hunks or M danger hunks says "too big
   to review — ask for it split" and refuses.
4. **Accessibility:** works under `NO_COLOR` (set and non-empty → no ANSI
   colour; it does not govern bold or underline,
   [no-color.org](https://no-color.org/), updated 2026-11-03). A `--plain`
   linear mode for screen readers, one hunk per paragraph, word tiers. A
   `--json` mode emits the review document.
5. **Watch the noise:** log per device how often danger appears and how often
   it is refused. A danger rate that stays high with near-zero refusals is the
   residue-R5 failure, measured.

## Q5. TUI scaffolds

Licences were read from the raw LICENSE file unless marked.

| Project | Language | Licence | Termux | Fit |
|---|---|---|---|---|
| [Textual](https://github.com/Textualize/textual) | Python | MIT | reported working in an old Textual discussion (#583); not tested | Same language as the compiler and `tendcf-validate`; `textual serve` gives a browser view for free |
| [Toad](https://github.com/batrachianai/toad) | Python (Textual) | AGPL-3.0; "commercial licenses are available" ([README](https://raw.githubusercontent.com/batrachianai/toad/main/README.md), fetched 2026-11-13) | snippet only: resolved natively via uv (OpenHCSDev/agent-comms#4339, 2026-11-08) | An agent client with "side-by-side or unified diffs"; the closest existing "AI proposes, human approves a diff" screen; the README claims Linux and macOS only; last push 2026-05-26 |
| textual-diff-view (batrachianai) | Python | AGPL-3.0 | as Toad | The diff widget; last push 2026-05-27 |
| [Rich](https://github.com/Textualize/rich) | Python | MIT (not re-fetched) | yes | Syntax and tables for the CLI mode |
| [Ratatui](https://github.com/ratatui/ratatui) | Rust | MIT | yes | Wrong language; Codex CLI uses it (snippet) |
| [Bubble Tea](https://github.com/charmbracelet/bubbletea) | Go | MIT | yes | Wrong language |
| [lazygit](https://github.com/jesseduffield/lazygit) / [gitui](https://github.com/gitui-org/gitui) / jjui | Go / Rust / Go | MIT / MIT / MIT | lazygit 0.66.3, gitui 0.28.1 packaged | Hunk-navigation patterns to imitate |
| [delta](https://github.com/dandavison/delta) | Rust | MIT | git-delta 0.20.1 packaged | Line diffs only; the tendcf diff is structural |
| k9s | Go | Apache-2.0 | not checked | Pattern only |
| [Mosaic](https://github.com/JakeWharton/mosaic) | Kotlin (Compose runtime) | Apache-2.0 | not checked | Kotlin, matching tendcf-agent; experimental (0.18.0); active (push 2026-11-12) |
| diffnav, tview, Ink | Go, Go, JS | not checked (diffnav LICENSE 404) | — | — |

Table: independently checked 2026-11-13: weakened, corrected (the Textual,
Toad, textual-diff-view and Mosaic licences are confirmed; the Termux,
platform and activity cells were corrected).

**Recommend Textual, with Toad's approval and diff screens as the borrowed
scaffold.** tendcf code is GPL-3.0-or-later (map R7 / R10, map:118-120). GPLv3 §13 allows
combining with AGPLv3 code; this is from knowledge, because the gnu.org fetch
timed out. Not checked: the independent checker did not fetch it either; fetch
https://www.gnu.org/licenses/gpl-3.0.html §13 before the licence ruling. The combined program would carry AGPL's network clause for the
borrowed parts. That is a licence ruling for the operator (X-safety-11).
**Runner-up:** Textual plus MIT-only parts (Rich Syntax, our own hunk list in
the lazygit/gitui style). It is more code to write but has no licence question.

## Q6. The same review on a phone

1. **Termux TUI** (the Textual app under Termux, or over SSH) serves the
   sysadmin adopters in G1. It does not serve the long-run user, who has no
   admin skill.
2. **Native Compose screen in tendcf-agent** (Kotlin, R4) serves the G1
   long-run user, with the same tiers, glyphs, words and friction. Step 2
   (Android) is deferred at `eefea3c` (map:1160) and G5 now puts Android
   second, so this screen sits on the critical path.
3. **Consistency mechanism:**
   1. The device produces one **review document**, in canonical JCS, holding:
      hunks with key paths, findings, tiers, score, caps applied, band,
      `If this is wrong` class, and template strings.
   2. Renderers only render it. They compute nothing.
   3. Golden fixtures hold every renderer: a fixture review document, and its
      expected `--plain` text and screen snapshot. This is the pattern residue
      R22 sets for the projector (map:1035; D45 at map:1243).
4. **Rules once, interpreters twice:** `review-rules.json` is interpreted by
   Python (`tendcf-validate`) and Kotlin (tendcf-agent), with a shared
   conformance corpus (diff in → review document out, byte-identical). The AI
   scan goes through the advisor on both platforms.

## Q7. Where scan and screen attach; what to sign and log

1. **Compiler side (preview):** `tendcf compile` runs the rule layer over the
   release diff and prints the review document. CI fails on an uncovered kind.
   This is a preview only (§9.1, §9.11).
2. **Device side (authority):** in `propose GOAL` (VAL:457-459, Step 9), after
   the device diff and before the briefing:
   1. rules;
   2. optional `--simulate-json` preview (VAL:489);
   3. AI scan via advisor;
   4. review document;
   5. render;
   6. local yes or refuse.
3. **Sign:** set `briefing_sha256` to the SHA-256 of the review document,
   and make it **required whenever a review was shown**. Today it is optional
   (`schema/approval-record.schema.json:35-36`). The review document embeds
   the rule-set digest, scanner version and AI model ids, so the approval binds
   to exactly what was shown.
4. **Log (JSONL, map §8):**
   1. scanner version, rule-set digest, AI model ids and output hashes;
   2. score, band and caps applied;
   3. UI mode (`cli`, `tui`, `termux`, `android`) and per-hunk
      acknowledgements;
   4. time to decide, and verdict.

   These are Q10's countable metrics.
5. **First build:** `adopt FILE` should print the structural diff against the
   current goal file and its rule findings, and ask for confirmation. This
   meets G4's "see and refuse" for root on the host now, before Step 9
   (X-safety-03).

## Response items

### X-safety-01: R14, the safety review, as a requirement

**Target:** `docs/architecture/architecture-DEFINITIVE-v3.md` §2 "Requirements
(normative)", at the sentence beginning "**R13** AI agents are the primary
authors."
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** G4 is a requirement on every change, and §2 has none for it. R13
makes AIs the authors but nothing requires that what they write is scanned,
scored or shown with graded emphasis. The goal definition says no document
describes the score, the highlighting or the TUI (`00-goal-definition.md:102-103`).
The proposed text keeps G4's wording, a confidence out of 100%; showing a score
out of 100 instead is an option for the operator, with its reasoning in
X-safety-10.
**Evidence:** map:103-125; `docs/review-2026-11-13/00-goal-definition.md:31-37`
**Proposed text:**

> - **R14** Every change is shown before it applies. The device computes the
>   exact structural diff (§9.1), runs the review rules
>   (`schema/review-rules.json`) and, where the owner has enrolled one, an AI
>   scan through the advisor slot (§11). It shows the safety confidence out
>   of 100% (or a score out of 100, per the ruling on X-safety-10),
>   the checks behind it, and each hunk at a tier (plain, notice, caution,
>   danger) whose friction rises with risk. The owner can refuse every change.
>   AI findings may lower the score; they never raise it, never lift a cap or
>   a ceremony class, and never authorize. One review document is rendered by
>   the command line, the TUI and tendcf-agent alike, and its hash is bound
>   into the approval record.

**Merge:** needs the operator's ruling first (X-safety-10, the number's
wording); otherwise insert after it (as a new requirement; the next free
number is R14)
**Checked:** verified (read map:103-125 at `eefea3c`; R6, R8 and R9 are absent
from the list, R14 is unused); independently checked 2026-11-13: weakened
(ruling), corrected: G4's "confidence" and "%" restored, and the "/100"
alternative left to the operator's ruling

### X-safety-02: validator proposal §15, the safety review

**Target:** `docs/architecture/tendcf-validate-proposal-2026-11-03.md`, new
section after §14 "Review record"
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** The proposal builds the component that computes the device diff
and runs `propose`. It says nothing about scanning, scoring or rendering. The
section below is written in the proposal's item voice.
**Evidence:** VAL:443-533 (§3), VAL:833-899 (§9), VAL:1130 (§14 is last)
**Proposed text:**

> ## 15. The safety review (G4)
>
> **(a) Question.** What does `tendcf-validate` show the owner before a
> change applies, and how is that bound to the yes?
>
> **(b) Options.**
>
> 1. Diff only: print the structural diff, ask yes or no.
> 2. Diff plus rules: a rules-as-data file over goal-file key paths sets a
>    tier and an "if wrong" class per hunk, and a capped score.
> 3. Option 2 plus an AI scan through the advisor slot, subtract-only.
>
> **(c) Consequences.** Option 1 meets "see and refuse" and nothing else in
> G4. Option 2 needs `schema/review-rules.json`, an interpreter here and one
> in tendcf-agent, and a conformance corpus. Option 3 adds the advisor
> exchange (Step 9) and treats the diff as hostile input to the AI: it sees
> the canonical diff as quoted data, never the author's prose; a finding
> counts only when it cites a key path in the diff.
>
> **(d) Recommendation.** Option 1 in the first build, through `adopt`
> (§9). Option 2 before any second host is enforced. Option 3 at Step 9.
> The output of all three is one review document (JCS), whose SHA-256 is
> `briefing_sha256` in the approval record. The figure is shown as G4 words
> it, a confidence out of 100%, unless the owner rules for "NN/100" until a
> calibration corpus exists (X-safety-10). Caps: any lockout, privilege or
> management finding ≤ 40; a check not run ≤ 60; an uncovered kind ≤ 70.
> Option for the owner's ruling: a top figure of 95, never 100, because no
> check makes a change certainly safe and a high number is read as authority.
>
> **(e) Proof.** Golden fixtures: diff in, review document out,
> byte-identical between Python and Kotlin; `--plain` text and TUI
> snapshot per fixture; a test that an AI finding cannot raise a tier or a
> score; a test that an uncovered kind caps at 70; a test that a hostile
> string in `command` reaches the AI quoted and capped.

**Merge:** needs the operator's ruling first (the score semantics, X-safety-10;
the scaffold licence, X-safety-11); the structure can merge once those are
settled
**Checked:** inferred (design); anchors verified by reading VAL at `eefea3c`;
independently checked 2026-11-13: weakened (ruling), corrected: the figure's
wording, and the cap at 95, are presented as options for the operator's
ruling

### X-safety-03: the first build's `adopt` shows the diff

**Target:** `docs/architecture/tendcf-validate-proposal-2026-11-03.md` §9
"Minimal first build", at the sentence beginning "*Consent.* No approval
record, nonce,"
**Kind:** ruling-drift
**Goal:** G4
**Weight:** blocks-goal
**Finding:** G4 says nothing changes a device except as a difference the owner
can see and refuse. In the first build "'Approved' means 'adopted by root on
the host'", and `adopt` shows nothing. The owner is root there, so showing the
structural diff against the current goal file costs only the diff code §9.2
needs anyway, and closes the gap now.
**Evidence:** VAL:867-871
**Proposed text:**

> 1. *Consent.* No approval record, nonce, `approval_seq` or advisor. No
>    consented host is admitted. "Approved" means "adopted by root on the
>    host", and `adopt` first prints the structural diff (map §9.2) against
>    the current goal file and asks for a yes; `--yes` exists for tests
>    only and is logged.

**Merge:** needs the operator's ruling first (it changes first-build scope)
**Checked:** verified (read VAL:864-876); independently checked 2026-11-13: confirmed

### X-safety-04: `briefing_sha256` is required when a review was shown

**Target:** `docs/architecture/architecture-DEFINITIVE-v3.md` §9.1 "Where the
diff is computed (E1 §5.1)"; and
`schema/approval-record.schema.json` property `briefing_sha256`, description
"Optional: binds the record to the briefing"
**Kind:** add
**Goal:** G4
**Weight:** misleads
**Finding:** Unless the record binds what was shown, the owner's yes can be
reattached to a different rendering. With the field optional, a renderer that
skips the score or the danger tier produces an equally valid record. This
changes the approval-record schema, which the standing rule names as a design
ruling needing two frontier reviews.
**Evidence:** `schema/approval-record.schema.json:35-36`; `CLAUDE.md` standing
rule item 3 ("Design rulings (a `schema_version` bump …")
**Proposed text:**

> - When a review was shown, the approval record MUST carry
>   `briefing_sha256`: the SHA-256 of the JCS review document (hunks,
>   findings, tiers, score, caps applied, rule-set digest, scanner version,
>   AI model ids). A renderer MUST render only that document.

**Merge:** needs the operator's ruling first (schema change; two frontier
reviews)
**Checked:** verified (read the schema at `eefea3c`); independently checked 2026-11-13: confirmed

### X-safety-05: the score joins the semantic layer and never authorizes

**Target:** map §9.11 "Signing and delivery (D41, D42)", at the sentence
beginning "Verifiable layer authorizes. Semantic layer"
**Kind:** add
**Goal:** G4
**Weight:** improves
**Finding:** The score and the AI findings are new semantic-layer output. The
existing sentence covers the briefing but not a number. A number is likely to
be read as authority ("95, fine"), so it needs the same bar, stated.
**Evidence:** map:910-915; arXiv 2006.14779 (explanations raise acceptance
regardless of correctness)
**Proposed text:**

> The safety score and its findings belong to the semantic layer. Rule
> findings are mechanical; AI findings are DC-3 untrusted text. Neither
> authorizes, neither changes `ceremony_class`, and an AI finding can only
> lower the score.

**Merge:** insert after it
**Checked:** verified (read map:905-920); independently checked 2026-11-13: confirmed

### X-safety-06: the AI scanner is not the authoring AI

**Target:** map §11 "The person’s own AI (D39)", at the sentence beginning
"Proposing side and consenting side are"
**Kind:** add
**Goal:** G4
**Weight:** misleads
**Finding:** R13 makes AIs the authors, and the owner's AI is the advisor. If
the same model wrote the change and scans it, it is likely biased toward
approving it: LLM evaluators favour their own generations (arXiv 2404.13076),
and models grow more confident in answers framed as their own turn
(arXiv 2606.03437). The
diff is also attacker-controlled input to the scanner (JudgeDeceiver;
LongPIBench).
**Evidence:** map:975-976; [arXiv 2404.13076](https://arxiv.org/abs/2404.13076)
(not fetched by the checker; fetch it before merging);
[arXiv 2606.03437](https://arxiv.org/abs/2606.03437);
[arXiv 2403.17710](https://arxiv.org/abs/2403.17710);
[arXiv 2608.28411](https://arxiv.org/abs/2608.28411)
**Proposed text:**

> The AI that scans a change SHOULD NOT be the model that authored it, and
> sees only the canonical diff as quoted data, never the author's prose.
> The diff is hostile input to it. Two model families, where the owner has
> them, are better than one; their disagreement caps the score.

**Merge:** insert after it
**Checked:** verified (read map:953-976); independently checked 2026-11-13: weakened, corrected

### X-safety-07: Q10 gets its counters

**Target:** map §16 "Open questions (remaining)", item 10, at the sentence
beginning "Is a diff something a person"
**Kind:** add
**Goal:** G4
**Weight:** improves
**Finding:** Q10 says it is "countable once real diffs exist" but not what is
counted. The review log (Q7 above) gives the counters.
**Evidence:** map:1281-1286; guide:1566-1579
**Proposed text:**

> Count, per device: hunks per release, danger and caution hunks per
> release, time to decide, refusal rate by band, and how often the danger
> tier is shown and approved. A danger rate that stays high with near-zero
> refusals is the residue-R5 rubber stamp, measured.

**Merge:** insert after it (end of item 10)
**Checked:** verified (read map:1250-1290); independently checked 2026-11-13: confirmed

### X-safety-08: the phone review is a native screen, with Termux as the operator's path

**Target:** map §13 "Build order", Step 9 row "Consent surface + default
prompt + advisor slot."; related: §12 "Platforms" "Android (adapter #2)"
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:** Step 9 names a consent surface without a form. G1's long-run user
has no admin skill and G5 puts Android second, so a Termux TUI is not the
user's surface. Consistency across CLI, TUI and phone needs one rendered object.
**Evidence:** map:1167; map:1160 (Android deferred); G1, G5
**Proposed text:**

> | 9 | Consent surface + default prompt + advisor slot. One review document (R14) rendered three ways: command line (`--plain`, `--json`), TUI (Textual; also under Termux and SSH), and a native screen in tendcf-agent. Renderers compute nothing; golden fixtures hold all three. |

**Merge:** replace that row; needs the operator's ruling first (the Android
order is in other items' scope)
**Checked:** verified (read map:1152-1172); independently checked 2026-11-13: confirmed

### X-safety-09: tiers key to hunk paths; flagged hunks never collapse

**Target:** map §9.2 "Canonicalization and the shape of the diff (E1 §5.2)",
at the sentence beginning "Serialization noise is camouflage, so"
**Kind:** add
**Goal:** G4
**Weight:** improves
**Finding:** §9.2 makes the diff structural, keyed by `(domain, kind, id)`.
That key path is what review rules match, so the tier belongs to the hunk.
Display grouping (Q10 mentions it) must not hide a flagged hunk.
**Evidence:** map:576-590; map:1281-1286
**Proposed text:**

> Each hunk carries a review tier (plain, notice, caution, danger) set by
> rules matched on its key path. Display grouping MAY fold plain hunks; it
> MUST NOT fold a caution or danger hunk.

**Merge:** insert after the paragraph
**Checked:** verified (read map:576-590); independently checked 2026-11-13: confirmed

### X-safety-10: "out of 100%" or "/100"

**Target:** `docs/review-2026-11-13/00-goal-definition.md` G4, at the sentence
beginning "The owner is shown a safety"
**Kind:** question
**Goal:** G4
**Weight:** misleads
**Finding:** "Out of 100%" reads as a probability that the change is safe.
No method fetched gives that for LLM opinions of config: verbalised confidence
is overconfident, and conformal guarantees assume exchangeability, which a
hostile author breaks. A rule-capped score can be honest as "/100" with a
stated meaning, and can become a "%" only after calibration on labelled diffs.
**Evidence:** [arXiv 2306.13063](https://arxiv.org/abs/2306.13063);
[arXiv 2305.18404](https://arxiv.org/abs/2305.18404);
[arXiv 2001.02114](https://arxiv.org/abs/2001.02114)
**Proposed text:**

> The owner is shown a safety score out of 100, with what it means, an
> explanation of why that figure was chosen, and the questionable code
> highlighted more dramatically the less safe it looks. It becomes a
> percentage once calibrated against labelled changes.

**Merge:** needs the operator's ruling first (wording of the agreed goal)
**Checked:** inferred (from the cited papers); independently checked 2026-11-13: confirmed

### X-safety-11: borrow table gets a TUI row, and a licence ruling

**Target:** map §6 "Supervisors, packages, and what we borrow (D36)", table
under "**Take (code or a thin wrapper)**"
**Kind:** add
**Goal:** G4
**Weight:** improves
**Finding:** G4 says the TUI is built on a borrowed scaffold. The borrow
table is where the map records borrowings. The best-fitting scaffold (Toad,
`textual-diff-view`) is AGPL-3.0, while tendcf is GPL-3.0-or-later. Both
AGPL candidates have had no push for about six months (Toad 2026-05-26,
textual-diff-view 2026-05-27).
**Evidence:** map:332-345; [Toad README](https://raw.githubusercontent.com/batrachianai/toad/main/README.md)
("licensed under the AGPL"); map:118-120 (R7 / R10)
**Proposed text:**

> | Review TUI | [Textual](https://github.com/Textualize/textual) (MIT); approval and diff screens from [Toad](https://github.com/batrachianai/toad) and textual-diff-view (AGPL-3.0, licence ruling D__); MIT-only fallback: Rich + our own hunk list |

**Merge:** needs the operator's ruling first (AGPL code in a GPL-3.0 project)
**Checked:** verified (licence files fetched); GPLv3 §13 compatibility not
fetched (gnu.org fetch timed out); independently checked 2026-11-13: confirmed

### X-safety-12: "exact difference" is of the goal file, not of effects

**Target:** map §9.10 "What this does not fix", at the sentence beginning
"**Effects versus declarations** (TC-23) is"
**Kind:** add
**Goal:** G4
**Weight:** misleads
**Finding:** G4's "exact, mechanically checked difference" is met for
declarations only. The screen must say so, or a high score reads as a promise
about what the device will do. A `--simulate-json` preview narrows this for
files and packages; the activation gap remains.
**Evidence:** map:853-876; VAL:489
**Proposed text:**

> The review screen says this in words: the score covers the declared
> change; what the device will actually do is previewed only for files and
> packages (`--simulate-json`), and not for services starting or running.

**Merge:** insert after it
**Checked:** verified (read map:853-876); independently checked 2026-11-13: confirmed

## Ideas and risks

1. **Risk: score as authority.** People anchor on numbers. A 95 on a change
   that drops an interlock, only because the rule set lacks a rule, is worse
   than no score. Mitigation: the uncovered-kind cap, and, if the operator
   rules for it, a 95 maximum.
2. **Risk: AI budget.** Two families per change on every device is real
   cost. Default to one AI via the advisor, two for privileged or baseline
   ceremonies.
3. **Risk: the Kotlin and Python rule interpreters drift.** Mitigation: the
   shared conformance corpus, run in Linux CI and the Android build.
4. **Risk: AGPL creep.** Borrowing Toad screens makes the review TUI AGPL in
   effect. The MIT-only runner-up avoids the question at the cost of more code.
5. **Idea: red-team corpus.** Seed hostile diffs: interlock removal hidden
   among 200 plain hunks, an injected "ignore previous" in `report`, `run_as`
   to root via a renamed id. Use them both as golden fixtures and as the start
   of the calibration corpus.
6. **Idea: "split this for me".** The long-run user cannot split a diff. Their
   own AI can be asked to re-propose it as smaller releases, each with a review.
   This also addresses residue R15, counter-proposal fatigue.
7. **Idea: teach on refusal.** G1 wants the AI to teach. A refused danger
   hunk links to a plain-words page per rule id, shipped with the rule set.
8. **Risk: Termux is not the phone answer.** A non-admin user will not run a
   TUI in Termux. Without the native screen, G4 on Android is met only for
   operators.
9. **Risk: habituation over months.** Polymorphic confirmation helps, but the
   strongest lever is fewer danger prompts. Keep rules precise and track the
   danger-approve rate (X-safety-07).
10. **Idea: `textual serve`.** It gives a browser review for free on the Mac
   server. The review document stays the authority; the web view is another
   dumb renderer.

## Not checked

1. No tool ran. The score weights are starting values, not measured.
2. Not fetched (described from knowledge): Terraform plan JSON, OPA/conftest,
   Checkov, KICS, Trivy, Semgrep, tfsec, deadnix, vulnix, nvd, nix-diff,
   `nixos-rebuild dry-activate`.
3. GPLv3 §13 and AGPL compatibility: the gnu.org fetch timed out.
4. Licences not checked: diffnav (LICENSE 404), tview, Ink, Codex CLI, Rich
   (not re-fetched).
5. Textual and Mosaic on Termux: not run. The Toad on Termux claim is snippet
   only.
6. Snippet only, not read (dl.acm.org and PubMed blocked fetches):
   Anderson et al. CHI 2015 and CHI 2017; Vance et al. MISQ 2018; Goddard et
   al. 2012.
7. No real non-operator user tested; this matches the digest's G1 finding.

## Sources (all fetched 2026-11-13 unless marked)

1. arXiv 2604.04978 v3, 2026-10-22, https://arxiv.org/abs/2604.04978
2. arXiv 2306.13063 v2, 2024-03-17, https://arxiv.org/abs/2306.13063
3. arXiv 2606.03437, 2026-06-02, https://arxiv.org/abs/2606.03437
4. arXiv 2305.14975, 2023, https://arxiv.org/abs/2305.14975
5. arXiv 2207.05221 v4, 2022-11, https://arxiv.org/abs/2207.05221
6. arXiv 2306.10193, 2023, https://arxiv.org/abs/2306.10193
7. arXiv 2305.18404, 2023, https://arxiv.org/abs/2305.18404
8. arXiv 2403.17710 v5, 2025-08-24, https://arxiv.org/abs/2403.17710
9. arXiv 2302.12173, 2023, https://arxiv.org/abs/2302.12173
10. arXiv 2608.28411, 2026-08-28, https://arxiv.org/abs/2608.28411
11. arXiv 2312.12575, 2023, https://arxiv.org/abs/2312.12575
12. arXiv 2606.26590, 2026-06-25, https://arxiv.org/abs/2606.26590
13. arXiv 2601.14595, 2026, https://arxiv.org/abs/2601.14595
14. arXiv 2608.02672, 2026, https://arxiv.org/abs/2608.02672
15. arXiv 2609.28488, 2026, https://arxiv.org/abs/2609.28488
16. arXiv 2006.14779, 2021, https://arxiv.org/abs/2006.14779
17. arXiv 2001.02114, 2020, https://arxiv.org/abs/2001.02114
18. arXiv 2405.00623, 2024, https://arxiv.org/abs/2405.00623
19. Akhawe and Felt, USENIX Security 2013,
    https://www.usenix.org/conference/usenixsecurity13/technical-sessions/presentation/akhawe
20. Felt et al., CHI 2015, https://research.google.com/pubs/archive/43265.pdf
21. NO_COLOR, updated 2026-11-03, https://no-color.org/
22. Ansible check mode rst (devel branch),
    https://raw.githubusercontent.com/ansible/ansible-documentation/devel/docs/docsite/rst/playbook_guide/playbooks_checkmode.rst
23. statix README, https://raw.githubusercontent.com/oppiliappan/statix/master/README.md
24. Toad README, https://raw.githubusercontent.com/batrachianai/toad/main/README.md
25. LICENCE files (raw, main or master branch): textual, ratatui, bubbletea,
    lazygit, gitui, jjui, delta, k9s, toad, textual-diff-view, mosaic.
26. termux-packages build.sh: lazygit, gitui, git-delta.
27. Snippet only: OpenHCSDev/agent-comms#4339 (2026-11-08) and #4333;
    dl.acm.org/doi/abs/10.1145/2702123.2702322;
    dl.acm.org/doi/10.1145/3025453.3025896; dl.acm.org/doi/10.25300/MISQ/2018/14124;
    pubmed 21685142.

Last search run: a gnu.org search for GPLv3 §13 found the licence page; the
scrape of it timed out (one URL, not a firecrawl outage). No new source found
that changes the recommendation.

## Withdrawn after checking

None. The independent checker refuted no claim in this report.
