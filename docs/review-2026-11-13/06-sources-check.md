# 06. Sources check: how the paper and guide use their sources

**Target:** `docs/paper/tendcf-architecture-paper.md` (P) and
`docs/paper/tendcf-architecture-guide.md` (G), wherever they cite a source.
**Base commit:** eefea3c
**How this was produced:** one reviewing agent (Claude Opus), then an
independent checking agent that tried to refute each finding; nothing was
executed unless an item says so.
**Item counts by Weight, after corrections:** 29 items: misleads 14,
improves 10, nit 5. None was withdrawn. (Two items, P-§3.1-s28 and
P-§3.2-s29, were added on 2026-11-13 from the source re-fetch,
`checks/v7-refetch.md`.)

This is a read-only review; no repository file was changed.

The status is `partial`. Round 2 (this update) fetched docs.bcfg2.org (over
plain http), docs.cfengine.com and every cited reference that open access
allows. What is still unread: the body of [9] (publisher elided the
abstract; ACM DL refused the fetch: paywalled), the [24] blog post at the
cited URL (both blog hosts failed; the balena docs page that links to it
was read instead), the [29] Jira ticket (the page rendered as an empty
"Jira" shell, so it needs a browser session or login), and the full texts
of [5], [6], [7], [8], [14] and [28], of which only the abstract or first
pages were read. Section D has the list. Every Bcfg2 claim was checked
against a primary source.

Update 2026-11-13 (`checks/v7-refetch.md`): once the web and library tools
were repaired, [9] (in the author's JACM-layout copy; the official ACM copy
stayed unreachable), the [24] blog post, the [29] ticket (through the public
REST endpoint), the Promise Theory book [6] and Burgess 2005, and the full
text of [28] were read. What remains unread of those: the official ACM copy
of [9]. The sentences below that name these as unread describe the state
before that pass.

Local primary copies used, extracted read-only to text. `B03` is CLUSTER03
[1], `B05` is LISA '05 [2], `B06` is LISA '06 [3], `B08` is the 2008 booklet
[4]. Line anchors `Bnn:LLL` point into a
plain-text extraction of those papers, taken from the PDFs in a local Bcfg2
source checkout (`doc/papers/*.pdf`).

Verdict counts over 59 claims: 35 accurate, 12 overstated, 8 wrong, 4
unverifiable. (Round 1 was 40 claims: 22, 9, 7, 2. Round 2 changed no
earlier verdict. It re-sourced T3-T9, T15, T18, T23 and T28 to the Bcfg2 and
CFEngine documentation and added T41-T59: 13 accurate, 3 overstated, 1
wrong, 2 unverifiable.) After the independent check, T16 moved from wrong
to overstated: 35 accurate, 13 overstated, 7 wrong, 4 unverifiable. The
2026-11-13 re-fetch resolved all four unverifiable rows: T27 refuted, T40
and T44 weakened, T59 confirmed; T54 stays overstated, with its blog post
now read.

Bcfg2 docs used (version 1.3.6, all fetched over http): `BI` =
http://docs.bcfg2.org/server/bcfg2-info.html, `BA` =
http://docs.bcfg2.org/client/tools/actions.html, `BS` =
http://docs.bcfg2.org/server/plugins/structures/altsrc.html, `BD` =
http://docs.bcfg2.org/server/plugins/structures/deps.html, `BP` =
http://docs.bcfg2.org/server/plugins/generators/packages.html, `BB` =
http://docs.bcfg2.org/server/plugins/structures/bundler/index.html, `BG` =
http://docs.bcfg2.org/server/plugins/version/git.html, `BM` =
http://docs.bcfg2.org/client/modes.html, `BT` =
http://docs.bcfg2.org/getting_started/index.html.

## A. Claims table

| # | Work | URL fetched | Claim (section) | Verdict |
|---|---|---|---|---|
| T1 | [1] Desai et al., BCFG, CLUSTER03 | local B03; venue confirmed at https://github.com/Bcfg2/bcfg2/raw/refs/heads/master/doc/appendix/papers.txt | P §4.2: verification runs in both directions, "no less … no more" | accurate |
| T2 | [1] cited for "comprehensive by convention … **extra entry**, a first-class reported category [1, §2.2]" | local B03:76 | P §4.2 | overstated. [1] is BCFG v1, which says the description "must be comprehensive", a requirement, and uses the term "extra configuration fragments". The words "By convention, Bcfg2 assumes goals are comprehensive" are in [4] (B08:529). |
| T3 | [4] booklet §2.2.1 | local B08:526; BB | P §6.1: the bundle is the re-verification scope | accurate ("validated collectively; that is, all entries get reverified"; BB: "groups of inter-dependent configuration entries") |
| T4 | [4] §A.2.1 Actions | local B08:2296; BA | P §6.1, G §12: a failing pre-action blocks the bundle | accurate (BA: "a failing pre-action will cause no modification of the enclosing bundle to be performed") |
| T5 | [4] §5.2; bcfg2-info doc | local B08:1648; BI; https://github.com/Bcfg2/bcfg2/blob/master/doc/server/bcfg2-info.txt | P §6.2, G §4: "`buildfile` renders exactly the artifact a named client would receive" | **wrong**. `buildfile` "constructs a single ConfigFile entry for a client". BI: "buildfile — Perform the entry binding process on a single entry"; "build — Build the full configuration specification". The full client goal is `build`. |
| T6 | same | B08:1645 (BI 1.3.6 no longer lists `buildall`) | P §6.2: "the `buildall` variant diffs every client's output across server upgrades" | **wrong**. `buildall` "builds individual client goals for each configured client", and is "frequently used to test server code upgrades". The diff is `bcfg2-admin compare`. |
| T7 | [4] §3.2 tutorial | local B08:1049, 1054; BT | P §4.2, G §11: first run `Unmanaged entries: 2308`; "the whole deployment story there is grinding the second number down" | overstated. The number is right, but it is one tutorial client, and the text says only "Over time, we will reduce this number". It is not a deployment story. BT, the current tutorial, is closer to the paper's reading ("Your goal now is to migrate each of those … up to the 'Correct entries' line"), but it is still a tutorial (242 entries there). |
| T8 | [2], [4] | local B05, B08 | P §9.3: "The Bcfg2 deployment ground 2308 unmanaged entries down over months with a person whose job that was". G §18 Q3: "Bcfg2's deployment had a person whose job that was" | **wrong**. 2308 is booklet tutorial output. No source has a role dedicated to grinding the count down. |
| T9 | [4]; Packages plugin doc; Desai, "Pay As You Go" (AUUG 2005) | BP; BD; BB; https://github.com/Bcfg2/bcfg2/raw/refs/heads/master/doc/server/plugins/generators/packages.txt; https://web.archive.org/web/2012/ftp://ftp.mcs.anl.gov/pub/bcfg/papers/pay-as-you-go.pdf | P §5.1 heading and body, G §10: "Bcfg2 deliberately built no dependency graph … machinery its author chose not to build" | overstated. Packages "provides a prerequisite resolution mechanism … dependencies are resolved, and automatically added" (versionadded 1.0.0). Pay As You Go: "It also provides automatic dependency handling". BP: the resolver runs "before entry binding" and "determines a superset of packages that will fully satisfy dependencies"; `[packages] resolver` defaults to on. BD: the Deps plugin states "Package X requires Package Y". Bcfg2 infers membership but has no ordering graph. No source supports "deliberately". |
| T10 | Bcfg2 project | same Packages URL; `docs/architecture/orchestration-research-2026-08-13.md` §4 ("docs last built 2016, last repo push 2023-11") | P §5.1, G §10: "two decades of production behind it" | overstated (Bcfg2 started c. 2004; the project is dormant) |
| T11 | [4] | local B08 (client loop) | P §5.1: repeat while pending operations decrease | accurate |
| T12 | [3] | https://www.usenix.org/legacy/events/lisa06/tech/full_papers/desai/desai.pdf | P §5.2: the server builds a client's configuration on request | accurate |
| T13 | [2] | https://www.usenix.org/legacy/events/lisa05/tech/full_papers/desai/desai.pdf; B05:167 | P §5.3, §6.4, G §18 Q5: reports bought administrator trust | accurate ("This single factor had more impact on administrator trust in Bcfg2 than all others") |
| T14 | [2] versus [4] | B05:160; B08:2201-2206 | P §5.3 and §9.5: "'No consumer yet' is exactly the reasoning that LISA '05 argues against … §6.4 records the same paper telling us to build reporting *early*" | **wrong source**. "Set up the reporting system early … Deploy it as soon as possible" is in booklet [4] §8.1, Deployment Tips. LISA '05 says the opposite order happened: "The deployment culminated with the implementation of a robust reporting infrastructure". |
| T15 | [3] | LISA '06 URL above; BG | P §6.3: revision stamping, a served log, past state reconstructible, exposure windows | accurate (BG: each check-in will "include the current repository revision in the reports/statistics") |
| T16 | [3], [2] | LISA '06 and LISA '05 URLs; B05:47 | P §6.3: "the paper's always-on cluster" | overstated ("always-on" is loose, not false; corrected on independent check). The environment is a division of "several hundred" workstations, servers and clusters, with a maintenance-window cluster (B06:246). |
| T17 | [2] | LISA '05 URL | P §6.4, §8: four months, primarily one person; the pivot to information presentation | accurate |
| T18 | [2], [3] | B05:139-141; LISA '06 URL ("nagging email"); BM | P §6.4: servers ran dry-run nightly and the state was mailed to the administrator | accurate (BM: dry-run "prevents the client from making changes" and still reports) |
| T19 | [2] | B05:139-144 | P §6.4: "auto-apply reserved for workstations" | overstated (nit). Cluster nodes also applied, "between jobs". |
| T20 | [2] | LISA '05 URL | P §8: 3 FTE before, 1/3 to 1/2 FTE after, about 200 people | accurate |
| T21 | [3] | LISA '06 URL | P §6.5: the limits of the state machine | accurate |
| T22 | [3] | B06:201, 211 | P §2.7 (the helpers paragraph, "those stall the *fleet*") and G §13 | overstated. LISA '06 offers mitigations: "limit per-operation checks to a series of machines that are pertinent", and "query a workflow for blocking issues". |
| T23 | [4] A.1.2 / §6.8 | B08:1954-1964, 2268; BS | P §6.5, G §13: `altsrc` | accurate (BS: "entry name remapping for the purpose of data binding", new in 0.9.5) |
| T24 | G §12 hyperlink "Bcfg2 Actions" pointing to the LISA '06 PDF | LISA '06 URL | G §12 | **wrong link**. LISA '06 does not describe Actions; the source is [4] §A.2.1. |
| T25 | internal count | P:38, P:1917, P:1941, G:129-134, G:1638 | Abstract "four of its load-bearing ideas"; G "Six ideas" (six if Actions and bundle scope count separately); Acknowledgements "four Bcfg2 papers" | **wrong** (inconsistent). Desai's AUUG 2005 "Pay As You Go" is a fifth paper, listed in the Bcfg2 papers appendix, and is not cited. |
| T26 | [1]-[3] bibliographic data | papers.txt URL; LISA PDFs | author lists, venues, pages | accurate |
| T27 | [6] Burgess and Bergstra, Promise Theory | https://markburgess.org/promises.html (landing page); the book, markburgess.org/BookOfPromises.pdf, ch. 1 and 17, read in full 2026-11-13 | P §2.3, G L316-348: Promise Theory "was formalized … specifically to rule out client-server protocols that push data to a controller" | refuted. The book (ch. 17.2) says Promise Theory was "originally invented to discuss the issues surrounding this autonomous operation, and voluntary cooperation" and "is not about protocol modeling"; Burgess 2005 builds client-server interactions out of promises (book and paper read 2026-11-13; see P-§2.3-s21 and 01 P-§2.3-02). |
| T28 | [23] CFEngine | https://docs.cfengine.com/docs/lts/overview/client-server-communication/; https://docs.cfengine.com/docs/lts/getting-started/01-installing-cfengine/general-installation/installation-community/; also *Learning CFEngine* ch. 3 | P §2.3: hub-and-spoke is the textbook setup, and a host can bootstrap to itself | accurate ("You should bootstrap the policy server first to itself"; "The host that other hosts are bootstrapped to automatically assumes the role of policy server"; "The Policy Server must be bootstrapped to itself") |
| T29 | [21] cdktf | https://github.com/hashicorp/terraform-cdk | P refs: "deprecated December 10, 2025" | accurate ("archived by the owner on Dec 10, 2025") |
| T30 | [26] TUF spec | https://theupdateframework.github.io/specification/latest/ | P L473 ("unremarkable TUF [26]"), G L554: the trusted root ships out of band; later rotation needs a threshold of old and new keys | accurate ("MUST ship with trusted root keys"; version N and N+1 thresholds) |
| T31 | [11] Liu et al. | https://arxiv.org/abs/2307.03172 | P §3.1 and §3 item 7: accuracy drops when the relevant fact is in the middle | accurate |
| T32 | [12] Kon et al., IaC-Eval | https://proceedings.neurips.cc/paper_files/paper/2024/hash/f26b29298ae8acd94bd7e839688e329b-Abstract-Datasets_and_Benchmarks_Track.html | P §3.1: GPT-4 at 19.36% "on real-world AWS scenarios" | accurate (pass@1 19.36%; the source says "458 human-curated scenarios", so "real-world" is a nit) |
| T33 | [13] Nekrasov et al. | https://arxiv.org/html/2512.14792 (full text) | P §3.1: IaC-Eval "isolates why", naming "Contextual Reasoning Failure — missing or incorrect cross-resource references … a distinct, substantial failure category" | overstated. CRF is 7.0% of technical errors (Table 6) and 47.6% of intent errors. Missing elements are classed as Incompleteness. CRF covers "conflicting arguments … incorrect dependencies". |
| T34 | [13] | same, Table 6 | P §3 item 4: about two-thirds invalid or nonexistent references, about a quarter omissions, syntax under 2% | accurate (65.0%, 26.5%, 1.5%) |
| T35 | [15] Wang and Zhang | https://arxiv.org/html/2509.19931 (full text) | P §3.2 item 1: retrieving "just the relevant fragment … instead of the whole specification, improves the generated result directly" | overstated. "Simply providing the documentation … does not help". Specific documentation helps less-proficient models; proficient models "perform better under the Once w/ Whole Doc setting"; in Fig. 5, "Once w/ whole doc yields the best results". |
| T36 | [15] | same | P §3 item 2: worked examples consistently outperform prose | accurate ("examples consistently outperform descriptions"; one domain, small open models) |
| T37 | [16] Tam et al. | https://arxiv.org/html/2408.02442 (full text) | P §3 item 8: no format wins consistently | accurate ("JSON is more consistent however it does not always outperform other format"). The single YAML-over-JSON case was not located. |
| T38 | [17] Gloaguen et al. | https://arxiv.org/html/2602.11988 (full text, v3) | P §3: no success gain; cost up "more than a fifth" | accurate (20% and 23%, p < 0.001%) |
| T39 | [17] | same, §4.2 and Table 3 | P §3.2 item 9: "model-generated files specifically performed worse than supplying no context file at all" | overstated. The drops were 0.5 and 2 points, p = 0.87 and 0.37, which the authors read as "no significant effect on performance". The one significant result is that LLM-generated files did worse than developer-written ones on one of the two benchmarks (CTXbench, p = 0.038). |
| T40 | [28] Srivatsa et al. | https://arxiv.org/abs/2404.00227 (abstract only) | P §3: LLM-for-IaC verification is "evaluated by textual similarity … rather than semantic or idempotence correctness" | weakened (full text read 2026-11-13: it reports Exact Match, BLEU, "Ansible Aware" and "Schema Correct" metrics, and for Terraform compares the plan with a reference; there is no mention of idempotence; see P-§3.2-s29). Nit: the venue is ICON 2023, while the reference gives 2024. |
| T41 | [5] Burgess 1995 | https://www.usenix.org/legacy/publications/compsystems/1995/sum_burgess.pdf (first pages) | P refs only (uncited) | accurate (bibliographic: "Computing Systems, Vol. 8, No. 3, Summer 1995") |
| T42 | [7] Couch and Sun | https://link.springer.com/chapter/10.1007/978-3-540-39671-0_4 (abstract, references) | P refs only (uncited) | accurate (DSOM 2003, LNCS 2867, pp. 28-40; "propose a stronger definition [of convergence] with improved algebraic properties") |
| T43 | [8] µPuppet | https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ECOOP.2017.12 (abstract) | P refs only (uncited) | accurate (ECOOP 2017, LIPIcs 74, 12:1-12:27; four authors as given) |
| T44 | [9] Banerjee, Naumann, Rosenberg | https://api.semanticscholar.org/graph/v1/paper/DOI:10.1145/2485982 (metadata; abstract "elided by the publisher"); ACM DL page failed | P §3.1 L991, P L1907: region logic "derives global heap invariants from purely local reasoning about mutation and separation" | weakened (read 2026-11-13 in the author's JACM-layout copy, software.imdea.org/~ab/Publications/lrgi1.pdf: it supports "heap-local reasoning about mutation and separation" and the factoring of global invariants "as they are relevant", not "derives global heap invariants from purely local reasoning"; the official ACM page was not reachable, see P-§3.1-s28). Bibliographic data accurate (J. ACM 60, 18:1-18:56, 2013); the title fits the claim. |
| T45 | [10] Tratt | https://tratt.net/laurie/blog/2026/local_reasoning_for_global_properties.html | P §3.1 L996-997: AI code generation "is reliably good at local … reasoning and unreliable at global reasoning" | overstated. Tratt: AI "often generates high-quality local … chunks of code, but often struggles" with global understanding, "at least as it stands right now". |
| T46 | [10] | same | P §3.1 L998-999: "his example is Rust's ownership system enforcing data-race freedom through local signatures" | accurate ("this property is enforced at the level of function signatures") |
| T47 | [10] | same | P refs: "tratt.net blog, July 2026" | **wrong** (nit). The post is dated 2026-06-30. |
| T48 | [14] Park, Zhou, D'Antoni | https://arxiv.org/abs/2502.05111 (abstract, v2) | P §3.2 L1133-1137: constrained decoding works "efficiently enough for production use rather than only as a research demonstration" | overstated. The abstract claims "17.71x faster offline preprocessing than existing approaches" while keeping state-of-the-art online mask cost. It makes no production claim. |
| T49 | [14] | same | P §3.1 L1015: grammar-constrained decoding constrains output to a grammar | accurate ("masking out tokens that will provably lead to outputs that do not belong to a specified context-free grammar") |
| T50 | [18] nixpkgs `systemd.nix` | https://raw.githubusercontent.com/NixOS/nixpkgs/master/nixos/modules/system/boot/systemd.nix | P §2.3 L345-346: NixOS modules compile to systemd unit files | accurate (`serviceToUnit` etc.; `"systemd/system".source = generateUnits { … }`) |
| T51 | [19] nix-darwin | https://github.com/nix-darwin/nix-darwin; https://github.com/nix-darwin/nix-darwin/tree/master/modules/system | P §2.3 L346-347: Nix modules to launchd agents and macOS defaults | accurate (`launchd.nix`, `defaults-write.nix`, `defaults/`; module bodies not read) |
| T52 | [20] cdk8s | https://github.com/cdk8s-team/cdk8s | P §2.3 L347-348: typed code to Kubernetes YAML | accurate ("cdk8s apps synthesize into standard Kubernetes manifests") |
| T53 | [22] Flux / GitOps | https://github.com/fluxcd/flux2; https://www.cncf.io/projects/flux/; https://web.archive.org/web/20180107011605/https://www.weave.works/blog/gitops-operations-by-pull-request | P §2.3 L392-394: GitOps "coined by Weaveworks and carried forward by Flux under the CNCF since 2019" | accurate ("'GitOps' is our name for how we use developer tooling to drive operations"; Flux "accepted to CNCF on July 15, 2019", graduated November 30, 2022). The 2017 post names Chef, Puppet and Ansible "diff alerts" as its prior art. |
| T54 | [24] balena | cited URL failed twice (blog.balena.io and www.balena.io/blog); read https://docs.balena.io/learn/deploy/offline-updates, which links to that post | P §2.3 L396-398: balenaCloud solves "offline-tolerant updates, connectivity-degradation tracking" | overstated. The documented offline update is a reflash from preloaded media that wipes device data, after which cloud state is patched "as if the device was online". The page has nothing on connectivity-degradation tracking. The blog post itself was read 2026-11-13 at the cited URL (HTTP 200): "all data on the device is wiped at this point, making this different from a typical software update process"; nothing on degradation tracking; the verdict and the replacement text in P-§2.3-s26 stand. |
| T55 | [24] | same docs page | P §2.3 L398-400: "it is centralized, and devices phone home to it" | accurate (devices are registered in balenaCloud and "should eventually establish a connection to balenaCloud") |
| T56 | [25] Kleppmann et al. | https://martin.kleppmann.com/papers/local-first.pdf (author PDF, 25 pages) | P L414: local-first literature, bibliographic data | accurate (Onward! '19, four authors; the "seven ideals" are wider grounds than the paper's, as P says) |
| T57 | [27] Dolstra | https://edolstra.github.io/pubs/phd-thesis.pdf | P §2.2 L327-328: purity "Nix's own build model is named for" | accurate (Utrecht, defended 18 January 2006; "a purely functional deployment model, which we implemented in the Nix system") |
| T58 | [23] Augments link | https://docs.cfengine.com/docs/3.21/reference-language-concepts-augments.html | G L215 link | accurate. Nit: it pins the 3.21 docs; LTS is now under `/docs/lts/` (https://docs.cfengine.com/docs/lts/reference/language-concepts/augments/, listed but not fetched). |
| T59 | [29] Jira CFE-4715 | https://northerntech.atlassian.net/browse/CFE-4715 (HTTP 200, empty body titled "Jira") | P refs only (uncited) | confirmed (read 2026-11-13). The browse page renders empty, but the tracker's public REST endpoint answers anonymously: CFE-4715 is a feature request, status Rejected, resolution Won't Do; all 26 tickets CFE-4715 to CFE-4740 were resolved on 2026-08-19 |

## B. Response items

### P-§6.2-s01: `buildfile` is a single-entry bind, not the whole client artifact

**Target:** `docs/paper/tendcf-architecture-paper.md` §6.2 "`buildfile`, which turned out to earn its place three times", at the sentence beginning "`bcfg2-info buildfile` renders exactly the artifact"
**Kind:** correct
**Goal:** G4 (an exact, mechanically checked difference; the lineage claim is what the reader checks first)
**Weight:** misleads
**Finding:** In Bcfg2, `buildfile` binds one ConfigFile entry for one client. The full per-client goal is `build`. `buildall` builds every client's goals and is used to test server upgrades. The diff comes from `bcfg2-admin compare`, not from `buildall`. Desai will notice this at once. The research note `docs/architecture/bcfg2-papers-2026-08-13.md` has the same error and is probably where it came from.
**Evidence:** B08:1645-1648: "buildall: … builds individual client goals for each configured client … buildfile … constructs a single ConfigFile entry for a client". BI (http://docs.bcfg2.org/server/bcfg2-info.html, also the GitHub source https://github.com/Bcfg2/bcfg2/blob/master/doc/server/bcfg2-info.txt): "buildfile — Perform the entry binding process on a single entry, displaying its results. This command is very useful when developing configuration file templates"; "build — Build the full configuration specification and write it to a file".
**Proposed text:**

> `bcfg2-info build` renders a named client's complete goal set server-side, without touching the client; `buildfile` does the same for a single entry; `buildall` builds every client's goals, which Bcfg2 uses to test a server upgrade; and `bcfg2-admin compare` diffs the output of `build` [4, §5.2]. For a pure compiler this is nearly free, and we built it first (`nix2cf buildfile`, §2.2; the name is borrowed from the single-entry command, the scope from `build`) because three separate justifications converge on it:

**Merge:** replace that sentence and the one after it
**Checked:** verified (local booklet text, the fetched GitHub doc and docs.bcfg2.org); independently checked 2026-11-13: confirmed (proposed text corrected: the booklet pairs `build`, not `buildall`, with `compare`)

### G-§4-s02: the same `buildfile` lineage in the guide

**Target:** `docs/paper/tendcf-architecture-guide.md` §4, at "The shape is [Bcfg2 `buildfile`](https://docs.bcfg2.org/)"
**Kind:** correct
**Goal:** G4
**Weight:** misleads
**Finding:** This repeats P-§6.2-s01. The link is `https://docs.bcfg2.org/`, the site root over https, which failed to fetch in this review; the same site works over plain http. The bcfg2-info page there says `buildfile` binds "a single entry".
**Evidence:** as P-§6.2-s01; BI
**Proposed text:**

> The shape is Bcfg2's [`bcfg2-info build`](http://docs.bcfg2.org/server/bcfg2-info.html) (the whole goal set for one named client; Bcfg2's `buildfile` does one entry).

**Merge:** replace that sentence
**Checked:** verified; independently checked 2026-11-13: confirmed

### P-§9.3-s03: 2308 is a tutorial client, not a deployment that was ground down

**Target:** paper §9 "Open questions", item 9.3, at "The Bcfg2 deployment ground 2308 unmanaged entries down"
**Kind:** correct
**Goal:** G8 (state 3 depends on the opt-out count falling without a dedicated role)
**Weight:** misleads
**Finding:** The 2308 count is booklet output for one tutorial client, followed by "Over time, we will reduce this number". No source says the Argonne deployment ground that number down, or that a person was assigned to it. LISA '05 says three people did most of the workstation rebuilds and that the configuration was migrated from Bcfg1. The question still stands without the false premise.
**Evidence:** B08:1049, 1054; B05:132-170 ("Three people performed most of the workstation rebuilds")
**Proposed text:**

> **9.3 Do `not-yet-migrated` counts actually get ground down, or accumulate?** Bcfg2's booklet expects its tutorial client's 2308 unmanaged entries to fall "over time" [4, §3.2], and the Argonne deployment had administrators whose work was configuration [2]. A fleet within this design's envelope (§1.1) has no such staff by construction. If the count only ever rises, the metric is decoration and default-on comprehensiveness is a permanent tax with no payoff.

**Merge:** replace the item's first two sentences
**Checked:** verified; independently checked 2026-11-13: confirmed

### G-§18-s04: the same claim in the guide's open questions

**Target:** guide §18, question 3, at "Bcfg2's deployment had a person whose job that was"
**Kind:** correct
**Goal:** G8
**Weight:** misleads
**Finding:** This repeats P-§9.3-s03.
**Evidence:** as P-§9.3-s03
**Proposed text:**

> Bcfg2's booklet expects the count to fall "over time", and Bcfg2 ran with administrators whose work was configuration.

**Merge:** replace that sentence
**Checked:** verified; independently checked 2026-11-13: confirmed

### G-§11-s05: "the deployment story there" overstates a tutorial

**Target:** guide §11, at "The deployment story there is grinding the second number down."
**Kind:** reword
**Goal:** G8
**Weight:** improves
**Finding:** This is the paper §4.2 sentence "the whole deployment story there is grinding the second number down" in short form. The source is a tutorial walkthrough of one client.
**Evidence:** B08:1049-1054
**Proposed text:**

> The booklet's next step is to grind the second number down over time.

**Merge:** replace that sentence. Make the same change in paper §4.2 ("the whole deployment story there is grinding the second number down" becomes "the booklet's next step is grinding the second number down")
**Checked:** verified; independently checked 2026-11-13: confirmed

### P-§4.2-s06: cite "by convention" to the booklet, not to CLUSTER03

**Target:** paper §4.2 "Comprehensiveness, default-on with a reasoned opt-out", at "Bcfg2's configuration goals are comprehensive by convention"
**Kind:** correct
**Goal:** G4
**Weight:** improves
**Finding:** [1, §2.2] describes BCFG v1. It says the description "must be comprehensive", which is a requirement rather than a convention, and calls the surplus "extra configuration fragments". The phrase "by convention", the "extra entry" category and the heuristic detection come from the booklet and LISA '05. Two-way verification is correctly attributed to [1].
**Evidence:** B03:76; B08:529 ("By convention, Bcfg2 assumes goals are comprehensive"); B05:71, 123 ("heuristics to discover this 'extra' configuration")
**Proposed text:**

> Unspecified state surfaces as an **extra entry**, a first-class reported category found by client-side heuristics [4, §2.2.1–2.2.2; 2]; the two-way check itself goes back to BCFG [1, §2.2].

**Merge:** replace the paragraph's last sentence
**Checked:** verified; independently checked 2026-11-13: confirmed

### G-§11-s07: restore "by convention"

**Target:** guide §11 "Extra entries", at "Bcfg2's configuration goals are comprehensive:"
**Kind:** correct
**Goal:** G4
**Weight:** nit
**Finding:** The guide drops "by convention". Bcfg2 does not mandate any client behaviour here.
**Evidence:** B08:529-531
**Proposed text:**

> Bcfg2's configuration goals are comprehensive by convention:

**Merge:** replace those words
**Checked:** verified

### P-§5.1-s08: Bcfg2 infers dependency membership; it has no ordering graph

**Target:** paper §5.1, the heading "We build dependency inference; Bcfg2 deliberately built no dependency graph" and the paragraph beginning "Bcfg2's answer to ordering is to not have one"
**Kind:** correct
**Goal:** G7 (the compiler's inference is an instrument open to challenge, so the challenge should be stated accurately)
**Weight:** misleads
**Finding:** Bcfg2 has dependency inference. The Packages plugin resolves package prerequisites and adds them automatically, and Desai's AUUG 2005 paper says Bcfg2 "provides automatic dependency handling". What Bcfg2 lacks is an ordering graph; the fixpoint loop and bundles stand in for one. No source says the author "deliberately" chose this or "chose not to build" more. "Two decades of production" also overstates a project that is effectively dormant (documentation last built in 2016, last repository push in November 2023). The disagreement as stated in §5.1 is real, but it is about ordering, not inference.
**Evidence:** BP and its GitHub source https://github.com/Bcfg2/bcfg2/raw/refs/heads/master/doc/server/plugins/generators/packages.txt ("Packages provides a prerequisite resolution mechanism … dependencies are resolved, and automatically added"; the resolver is on by default). BD (the Deps plugin: "Package X requires Package Y"). BB ("groups of inter-dependent configuration entries"). https://web.archive.org/web/2012/ftp://ftp.mcs.anl.gov/pub/bcfg/papers/pay-as-you-go.pdf ("This process loops correcting errors until no more progress can be made. It also provides automatic dependency handling"). `docs/architecture/orchestration-research-2026-08-13.md` §4 (dormancy)
**Proposed text:**

> ### 5.1 We infer an ordering graph; Bcfg2 has none
>
> Bcfg2's answer to ordering is to not have one. It does infer membership — the Packages plugin closes a package set over its prerequisites, and Desai describes the client as providing "automatic dependency handling" [Pay As You Go] — but nothing orders the result. The client's apply loop repeats while the number of pending operations decreases; bundles are the collective re-verification scope; there is no ordering to get wrong. That is simpler than what we are proposing, and it ran Argonne's MCS division for years [2, 3]. We are adding ordering machinery Bcfg2 did without.

**Merge:** replace the heading and that paragraph. Add the Pay As You Go reference (see P-refs-s16)
**Checked:** verified; independently checked 2026-11-13: confirmed (T9); T10's dormancy wording weakened, corrected (`docs/architecture/orchestration-research-2026-08-13.md:167`)

### G-§10-s09: the same in the guide

**Target:** guide §10, at "Bcfg2 deliberately built no dependency graph."
**Kind:** correct
**Goal:** G7
**Weight:** misleads
**Finding:** This repeats P-§5.1-s08.
**Evidence:** as P-§5.1-s08
**Proposed text:**

> Bcfg2 has no ordering graph. It closes package sets over their prerequisites, but its client simply repeats while pending work decreases. That is simpler, and it ran a large division for years.

**Merge:** replace the first three sentences
**Checked:** verified; independently checked 2026-11-13: confirmed

### P-§5.3-s10: "build reporting early" is the booklet's tip, not LISA '05's

**Target:** paper §5.3, at "'No consumer yet' is exactly the reasoning that LISA '05 argues against elsewhere, which is why §6.4 records the same paper telling us to build reporting *early*."
**Kind:** correct
**Goal:** G8 (log archive and monitoring on the Mac, state 1)
**Weight:** misleads
**Finding:** The tip is booklet §8.1, "Deployment Tips". LISA '05 reports the opposite order: the deployment "culminated" in the reporting infrastructure, and that infrastructure did the most for trust. The argument survives, with the right source and a more honest reading: LISA '05 shows what reporting bought, and the booklet, written later, advises building it first.
**Evidence:** B08:2201-2206 ("Set up the reporting system early … Deploy it as soon as possible"; "Master the server-side query tools early"; "Ease into deployment using dry-run mode"). B05:160-167
**Proposed text:**

> "No consumer yet" is exactly the reasoning the Bcfg2 booklet's deployment tips argue against [4, §8.1] — written after LISA '05 found that reporting, which came last there, did more for administrator trust than anything else [2] — which is why §6.4 adopts the tip to build reporting *early*. We may be applying one of their findings and ignoring another.

**Merge:** replace those two sentences; 01 P-§5.3-01 edits the sentence before and now carries the same booklet attribution
**Checked:** verified; independently checked 2026-11-13: confirmed

### P-§6.4-s11: the same attribution in §6.4 and §9.5

**Target:** paper §6.4 "Deploy reporting early, and dry-run as the default posture", at "And "deploy reporting early, not last" reframes", and §9.5 at "precisely the reasoning LISA '05 warns against"
**Kind:** correct
**Goal:** G8
**Weight:** misleads
**Finding:** "Two practices follow" reads as if both come from LISA '05. The dry-run practice is in LISA '05; "deploy reporting early" is booklet §8.1. §9.5 repeats the misattribution. Guide §18 Q5 is correct as written, because it cites only the trust finding.
**Evidence:** as P-§5.3-s10
**Proposed text:**

> And the booklet's deployment tip, "set up the reporting system early" [4, §8.1], reframes our local JSONL capture …

For §9.5:

> … "no consumer yet" is precisely the reasoning the Bcfg2 booklet warns against [4, §8.1], and we are taking one of its tips while declining another.

**Merge:** replace the quoted phrases in §6.4 and §9.5; for §9.5, make one edit with 01 P-§9-02, which replaces the whole item and must keep this booklet attribution if it names the source
**Checked:** verified; independently checked 2026-11-13: confirmed

### P-§6.3-s12: there is no "always-on cluster" in LISA '06

**Target:** paper §6.3 "Revision stamping", at "than in the paper's always-on cluster"
**Kind:** correct
**Goal:** G3 (often-off devices are the case the claim is about)
**Weight:** improves
**Finding:** LISA '06 describes a division network: workstations, critical servers that are never changed automatically, and a production cluster changed only in maintenance windows. "Always-on" is loose: the division mixed workstations, servers and a cluster changed only in maintenance windows, and the loose word weakens the contrast the sentence is trying to draw.
**Evidence:** B06:240-262; B05:47 ("several hundred")
**Proposed text:**

> … the reconstructibility is worth more here than on the paper's division network of mostly reachable workstations, servers and clusters.

**Merge:** replace the end of that sentence
**Checked:** verified; independently checked 2026-11-13: weakened, corrected (T16 is overstated, not wrong: B06:246 maintenance-window cluster, B05 "between jobs")

### P-§6.4-s13: workstations were not the only machines that applied automatically

**Target:** paper §6.4, at "auto-apply reserved for workstations"
**Kind:** reword
**Goal:** G4
**Weight:** nit
**Finding:** Workstations applied automatically, servers ran in dry-run with mailed state, and cluster nodes applied "between jobs". So auto-apply was not reserved for workstations.
**Evidence:** B05:139-144
**Proposed text:**

> … workstations applied automatically and cluster nodes only between jobs;

**Merge:** replace that phrase, as one edit of the sentence with 01 P-§6.4-01, which rewrites the same posture sentence
**Checked:** verified; independently checked 2026-11-13: confirmed

### P-§3-s14 (and guide §13, same text): one down client does not stall "the fleet"

**Target:** paper §2.7, the helpers paragraph at "those stall the *fleet* when one box is unreachable" (near "Not a distributed lock"), and guide §13 at the same phrase. The ID keeps its original "§3" label for stability; the passage is in §2.7.
**Kind:** reword
**Goal:** G3
**Weight:** improves
**Finding:** LISA '06 says one unreachable client can block a workflow. It also gives the mitigation: scope per-operation checks to the pertinent machines, and query a workflow for blocking issues. "The fleet" overstates this. §6.5's own wording, "a workflow", is the accurate one.
**Evidence:** B06:201-211
**Proposed text:**

> … not Bcfg2's LISA '06 state machine over *releases* — there one unreachable box can stall a whole workflow until an administrator scopes it out.

**Merge:** replace that clause in both documents
**Checked:** verified; independently checked 2026-11-13: weakened, corrected (target relabelled from §3 to §2.7; the mitigations at B06:201, 211 confirmed)

### G-§12-s15: the Actions link points to the wrong paper

**Target:** guide §12, at "[Bcfg2 Actions](https://www.usenix.org/legacy/events/lisa06/tech/full_papers/desai/desai.pdf)"
**Kind:** correct
**Goal:** G4
**Weight:** misleads
**Finding:** The LISA '06 paper does not describe Actions. The quoted behaviour ("unless exit status is ignored, a failing pre-action prevents modification") is booklet [4] §A.2.1, nearly verbatim. Paper §6.1 already cites [4, §A.2.1] correctly.
**Evidence:** fetched LISA '06 PDF (no Actions); B08:2296
**Proposed text:**

> Bcfg2 Actions ([*Configuration Management with Bcfg2*](https://www.usenix.org/short-topics/configuration-management-bcfg2), §A.2.1) are the shipped precedent:

**Merge:** replace the link. The USENIX Short Topics URL is not fetched; check it or cite the booklet without a link
**Checked:** verified (the claim); not checked (the replacement URL); independently checked 2026-11-13: confirmed

### P-refs-s16: four or five papers, four or six ideas; add Pay As You Go

**Target:** paper abstract "Bcfg2 supplies four of its load-bearing ideas", the closing summary at P:1917 "four of its load-bearing ideas", Acknowledgements "the four Bcfg2 papers"; guide §2 "Six ideas in this picture" and the guide's Acknowledgements
**Kind:** correct
**Goal:** G1 (adoptable: the credits must be checkable)
**Weight:** misleads
**Finding:** The paper says four ideas. The guide says six, which holds if Actions and bundle scope count separately: extra entries, Actions, bundle scope, `buildfile`, revision stamping and `altsrc`. The two documents disagree, four against six. Both say "four Bcfg2 papers", but [4] is a booklet. Desai's sole-author "Pay As You Go" (AUUG 2005) is in Bcfg2's own papers list, supports the fixpoint loop and dependency handling, and is not cited.
**Evidence:** P:38, P:1917, P:1941; G:129-134, G:1638; https://github.com/Bcfg2/bcfg2/raw/refs/heads/master/doc/appendix/papers.txt; the Pay As You Go URL above
**Proposed text:**

> Abstract: "Bcfg2 supplies `<N>` of its load-bearing ideas, credited in §6." Guide: "`<N>` ideas in this picture come from Bcfg2 …". Acknowledgements: "… on the Bcfg2 papers and booklet this work draws from …". New reference: "[30] N. Desai. *Pay As You Go: A Bcfg2 Configuration Management Approach* (title to be confirmed from the PDF). AUUG 2005. https://web.archive.org/web/2012/ftp://ftp.mcs.anl.gov/pub/bcfg/papers/pay-as-you-go.pdf"

**Merge:** needs the operator's ruling first (the count `<N>`: four, if Actions and bundle scope are one idea and `altsrc` is not load-bearing; five, if they are one idea and `altsrc` is; six, if Actions and bundle scope count separately). Use the same count in both documents and in 01 P-Abs-03
**Checked:** verified (the counts and the appendix); the exact title of the AUUG paper was not checked; independently checked 2026-11-13: weakened, corrected ("five listed" was a miscount; the guide's six holds if Actions and bundle scope count separately)

### P-refs-s17: four references are never cited

**Target:** paper References [5], [7], [8], [29]
**Kind:** cut | add
**Goal:** G7
**Weight:** nit
**Finding:** A count of in-text citations over the paper body found no `[5]` (Burgess 1995), `[7]` (Couch and Sun), `[8]` (µPuppet) or `[29]`. Their bibliographic data is accurate (T41-T43). Couch and Sun propose "a stronger definition [of convergence] with improved algebraic properties", which bears directly on §5.1's fixpoint, so cite it there rather than cut it.
**Evidence:** `rg` count over `docs/paper/tendcf-architecture-paper.md` at `eefea3c`; T41-T43, T59 URLs
**Proposed text:**

> (§5.1, after "repeats while the number of pending operations decreases") — convergence of exactly this kind has an algebraic treatment [7].

**Merge:** insert. Cut [5], [8] and [29], or cite them where they apply
**Checked:** verified (count, and the abstracts or first pages of [5], [7], [8]); [29] read 2026-11-13 through the tracker's public REST endpoint (T59: confirmed); sources re-fetched 2026-11-13: confirmed

### P-§3.1-s18: Contextual Reasoning Failure is not the main cause

**Target:** paper §3.1, at "Nekrasov et al.'s error taxonomy … isolates why, naming "Contextual Reasoning Failure" — missing or incorrect cross-resource references"
**Kind:** correct
**Goal:** G6 (the premise needs accurate evidence about where AI-written config fails)
**Weight:** misleads
**Finding:** In Nekrasov's Table 6, CRF is 7.0% of technical errors. Factual incorrectness is 65.0% and incompleteness is 26.5%. CRF leads only among intent errors (47.6%). The definition is "conflicting arguments … incorrect dependencies". Missing elements are classed as incompleteness. §3 item 4 uses the same table correctly.
**Evidence:** https://arxiv.org/html/2512.14792, Table 6, Table 7, §4.3.1 ("Contextual Reasoning Failure, responsible for 47.6% of all instances, is the most frequent LLM generation failure type associated with intent errors")
**Proposed text:**

> Nekrasov et al.'s error taxonomy of LLM-generated Terraform [13] shows where it goes wrong: two-thirds of technical failures are factually incorrect references (hallucinated or outdated arguments and resources), a quarter are omissions, and "Contextual Reasoning Failure" — inconsistent or wrongly dependent resources, the global-knowledge dependency §4.1 discusses below — is the leading cause of code that validates but does not do what was asked.

**Merge:** replace that clause
**Checked:** verified (full text); independently checked 2026-11-13: confirmed

### P-§3-s19: model-generated context files were not significantly worse

**Target:** paper §3.2 item 9 (the ID keeps its original "§3" label for stability), at "and model-generated files specifically performed worse than supplying no context file at all [17]"
**Kind:** correct
**Goal:** G6
**Weight:** misleads
**Finding:** LLM-generated files lowered resolution by 0.5 and 2 points, with p = 0.87 and 0.37. The authors read this as "no significant effect on performance". The significant finding is that developer-written files beat LLM-generated ones on one of the two benchmarks (p = 0.038). The paper's recommendation, minimal and hand-written, still follows.
**Evidence:** https://arxiv.org/html/2602.11988 §4.2 and Table 3
**Proposed text:**

> … inference cost rose by more than a fifth on average, and model-generated files did no better than having none, and significantly worse than developer-written ones on one of the two benchmarks (p = 0.038) [17].

**Merge:** replace the end of that sentence
**Checked:** verified (full text); independently checked 2026-11-13: weakened, corrected (target is §3.2 item 9, paper line 1185; the p = 0.038 result holds on one benchmark only)

### P-§3-s20: Wang and Zhang do not show "fragment beats whole specification"

**Target:** paper §3.2 item 1 (the ID keeps its original "§3" label for stability), at "retrieving just the relevant fragment of documentation, instead of the whole specification, improves the generated result directly"
**Kind:** correct
**Goal:** G6
**Weight:** improves
**Finding:** The study found that whole documentation alone does not help weak models, and that targeted documentation helps them. Stronger models did better with the whole document, and the whole document scored best in the format comparison (Fig. 5). The study covers PDDL with 8B to 32B open models. The lookup argument stands if it is scoped to weaker models.
**Evidence:** https://arxiv.org/html/2509.19931 §1, §4 ("for models less capable of generating PDDL, modular generation is more effective, as they tend to become overwhelmed"; "these PDDL-proficient models … perform better under the Once w/ Whole Doc setting")
**Proposed text:**

> … closely analogous work on generating planning-language code found that, for models that handle the language poorly, retrieving just the relevant fragment of documentation beats handing over the whole specification, which overwhelms them; stronger models did better with the whole document [15].

**Merge:** replace that clause
**Checked:** verified (full text); independently checked 2026-11-13: confirmed

### P-§2.3-s21: soften the Promise Theory purpose claim

**Target:** paper §2.3, at "Promise Theory was formalized as a model of autonomous agents specifically to rule out client-server protocols that push data to a controller [6]"
**Kind:** reword
**Goal:** G3
**Weight:** improves
**Finding:** The claim that Promise Theory was formalised "specifically to rule out client-server protocols that push data to a controller" is refuted. The book [6] (ch. 17.2) says Promise Theory was "originally invented to discuss the issues surrounding this autonomous operation, and voluntary cooperation" and "is not about protocol modeling". Burgess's 2005 DSOM paper introduced the promise as a measure of voluntary cooperation and builds client-server interactions out of promises, so the theory does not rule them out. Both sources support "no other agent can impose a promise on it", not "cannot be obliged". The autonomy point is enough for G3. This item and 01 P-§2.3-02 carry the same proposed text.
**Evidence:** https://markburgess.org/promises.html (landing page); the book, https://markburgess.org/BookOfPromises.pdf, ch. 1 and 17 ("originally invented to discuss the issues surrounding this autonomous operation, and voluntary cooperation"; "It is not about protocol modeling"); Burgess, DSOM 2005, LNCS 3775, DOI 10.1007/11568285_9, read through the library proxy ("no external agent can tell it what to do, without its consent"; promises rebuild "client-server interactions, dependencies and access control"). Read 2026-11-13.
**Proposed text:**

> In Promise Theory, which was developed to describe CFEngine's decentralised mode of operation, an agent can promise only its own behaviour and no other agent can impose a promise on it [6]. A design with no control node is the natural reading of that model, not this paper's invention, and it is one reason CFEngine is the current engine (§2.2).

**Merge:** replace that sentence, as one merged edit with 01 P-§2.3-02, which edits the same sentence and now follows this item's weight (`improves`)
**Checked:** verified (the book and Burgess 2005 read 2026-11-13); independently checked 2026-11-13: confirmed; sources re-fetched 2026-11-13: corrected

### X-s22: Desai's published view of CFEngine needs an answer

**Target:** paper §2.3 (why CFEngine), new paragraph
**Kind:** add
**Goal:** G7 (CFEngine is an instrument open to challenge)
**Weight:** improves
**Finding:** The first reader has written, twice, that CFEngine is close to manual or imperative administration. The paper builds on CFEngine and does not address this. One sentence that names the view and gives the paper's answer (promises plus a compiled, typed Site Model) would help.
**Evidence:** LISA '05 PDF: "Other tools, such as SystemImager and CFEngine, have a model that is not substantially different from manual system administration". Pay As You Go: "CFEngine … is designed around an imperative model".
**Proposed text:**

> Bcfg2's authors judged CFEngine's model "not substantially different from manual system administration" [2] and "imperative" [Pay As You Go]. Here CFEngine is only the convergence engine: the declarative, comprehensive specification is the Site Model, compiled into promises, which is the layer Bcfg2 says CFEngine lacked.

**Merge:** insert after "it is the actual reason §2 chooses CFEngine over the alternatives". Needs the operator's ruling on tone first
**Checked:** verified (quotes); independently checked 2026-11-13: confirmed

### P-§3.1-s23: Tratt says "often", not "reliably"

**Target:** paper §3.1, at "AI code generation is reliably good at local (e.g., function-level) reasoning and unreliable at global reasoning"
**Kind:** reword
**Goal:** G6
**Weight:** improves
**Finding:** Tratt hedges twice: AI "often generates high-quality local … chunks of code, but often struggles" with global understanding, and only "at least as it stands right now". The rest of the summary, including the Rust example, is accurate.
**Evidence:** https://tratt.net/laurie/blog/2026/local_reasoning_for_global_properties.html
**Proposed text:**

> … AI code generation, as it stands, often produces high-quality local (e.g., function-level) code but often struggles where a global understanding of the program is needed, so a language that lets a local author discharge a global

**Merge:** replace from "AI code generation is" to "discharge a global"
**Checked:** verified (full post); independently checked 2026-11-13: confirmed

### P-refs-s24: Tratt's post is dated 30 June 2026

**Target:** paper References [10], "tratt.net blog, July 2026"
**Kind:** correct
**Goal:** G7
**Weight:** nit
**Finding:** The post carries the date stamp 2026-06-30.
**Evidence:** same URL
**Proposed text:**

> [10] L. Tratt. *Local Reasoning for Global Properties.* tratt.net blog, 30 June 2026.

**Merge:** replace the first line of [10]
**Checked:** verified; independently checked 2026-11-13: confirmed

### P-§3.2-s25: [14] does not claim production readiness

**Target:** paper §3.2, at "efficiently enough for production use rather than only as a research demonstration [14]"
**Kind:** reword
**Goal:** G6
**Weight:** improves
**Finding:** Park et al. report "17.71x faster offline preprocessing than existing approaches" and state-of-the-art online mask cost. They say existing tools "require tens of minutes to preprocess common grammars". They make no production claim. Only the abstract was read.
**Evidence:** https://arxiv.org/abs/2502.05111
**Proposed text:**

> … to a formal grammar, and recent work cuts the grammar preprocessing that made this slow from tens of minutes by more than an order of magnitude [14] (§3.1).

**Merge:** replace from "efficiently enough" to "(§3.1)."
**Checked:** verified (abstract only); independently checked 2026-11-13: confirmed (abstract only)

### P-§2.3-s26: balena's offline update is a reflash, not offline tolerance

**Target:** paper §2.3, at "offline-tolerant updates, connectivity-degradation tracking [24]", and reference [24]
**Kind:** correct
**Goal:** G3 (often-off devices are the case the comparison is about)
**Weight:** improves
**Finding:** balena's documented offline update preloads a release onto boot media and reflashes the device, which wipes its local data. Cloud state is then patched "as if the device was online". That is a sneakernet path, not an agent that tolerates being offline, and the page says nothing about connectivity-degradation tracking. The "centralized, phone home" contrast is accurate. The blog post at the cited URL (blog.balena.io, "Offline Updates", 2021-02-12) was read on 2026-11-13: it says "all data on the device is wiped at this point, making this different from a typical software update process" and does not mention degradation tracking, so the reference URL may stay and the docs page is an alternative.
**Evidence:** https://docs.balena.io/learn/deploy/offline-updates; https://blog.balena.io/offline-updates-make-it-easier-to-update-balena-devices-without-the-internet/ (read 2026-11-13)
**Proposed text:**

> … balenaCloud is the closest working system solving the same problem — including offline updates for air-gapped devices by reflashing them from preloaded media [24] — with one real architectural difference …

and

> [24] balena. *Offline Updates.* balena documentation. https://docs.balena.io/learn/deploy/offline-updates

**Merge:** replace that dash clause and reference [24]. If the author has another source for degradation tracking, cite it instead of cutting the clause
**Checked:** verified (docs page; the blog post read 2026-11-13); independently checked 2026-11-13: confirmed (docs only); sources re-fetched 2026-11-13: confirmed

### G-§13-s27: deep-link the Bcfg2 `altsrc` page

**Target:** guide §13, at "[Bcfg2 `altsrc`](http://docs.bcfg2.org/)"
**Kind:** correct
**Goal:** G4
**Weight:** nit
**Finding:** The link goes to the site root. The plugin page exists and supports the text.
**Evidence:** BS
**Proposed text:**

> [Bcfg2 `altsrc`](http://docs.bcfg2.org/server/plugins/structures/altsrc.html)

**Merge:** replace the link target
**Checked:** verified; independently checked 2026-11-13: confirmed

### P-§3.1-s28: region logic supports heap-local reasoning, not "global invariants from purely local reasoning"

**Target:** paper §3.1, at "Banerjee, Naumann, and Rosenberg's region logic [9], which derives global heap invariants from purely local reasoning about mutation and separation" (paper L991-992; the later mention near L1907 is only "[9]", so no edit there)
**Kind:** correct
**Goal:** G6 (the premise needs accurate evidence)
**Weight:** misleads
**Finding:** [9] supports "heap-local reasoning about mutation and separation". Its introduction handles global invariants by factoring "parts as they are relevant", and the paper says it "facilitates heap-local reasoning about object invariants". "Derives global heap invariants from purely local reasoning" claims more than that. This replaces T44's earlier "unverifiable" verdict.
**Evidence:** Banerjee, Naumann and Rosenberg, J. ACM 60(3), Art. 18, 2013, DOI 10.1145/2485982. Read in the author's copy in the JACM layout, software.imdea.org/~ab/Publications/lrgi1.pdf (the ACM Reference Format line matches; the official ACM page answered HTTP 403, a Cloudflare challenge, on all three URL forms via the library proxy). Quotes: "heap-local reasoning about mutation and separation"; "facilitates heap-local reasoning about object invariants". Read 2026-11-13 (`checks/v7-refetch.md`, R1).
**Proposed text:**

> Banerjee, Naumann, and Rosenberg's region logic [9], which supports heap-local reasoning about mutation and separation, so that a global object invariant can be maintained by reasoning only about the part of the heap a command touches.

**Merge:** replace that sentence
**Checked:** verified (full text read 2026-11-13, in the author's JACM-layout copy; the official ACM copy was not reachable)

### P-§3.2-s29: [28] evaluates mostly against a reference solution, not by "textual similarity" alone

**Target:** paper §3.2, at "evaluated by textual similarity to a reference rather than by semantic or idempotence correctness [28]" (paper L1130-1132)
**Kind:** correct
**Goal:** G6
**Weight:** misleads
**Finding:** Srivatsa et al. report Exact Match, BLEU, "Ansible Aware" and "Schema Correct" metrics, and for Terraform compare the plan with a reference. So "textual similarity ... rather than semantic" is half right: schema and plan checks exist. Idempotence is absent from the paper (no hit for "idempot"). This replaces T40's "unverifiable" verdict.
**Evidence:** Srivatsa et al., arXiv:2404.00227, full text read 2026-11-13 from the PDF (6.4k words): "Exact Match, BLEU ... Ansible Aware ... Schema Correct". `checks/v7-refetch.md`, R17.
**Proposed text:**

> evaluated mostly against a reference solution (exact match, BLEU, schema checks, plan equality) rather than by running the result and checking idempotence [28]

**Merge:** replace that sentence
**Checked:** verified (full text read 2026-11-13)

## C. Missing prior work

Fetched in this review: the Bcfg2 papers list, Pay As You Go, Hummer et al. and Rehearsal. Each other entry is marked "not fetched" and should be checked before it is cited.

1. Desai, "Pay As You Go", AUUG 2005 (fetched, URL above). G2: Bcfg2's own case for incremental adoption, with representations ranging from literal to abstract, which maps onto YAML beneath Nix. The ordering claims in §5.1 also need it.
2. Traugott and Brown, "Why Order Matters: Turing Equivalence in Automated Systems Administration", LISA 2002, pp. 99-120 (citation confirmed in Hummer et al.'s reference list, fetched below; the paper itself was not fetched). Congruence versus convergence is exactly §5.1's ordering question and G4's "exact difference".
3. Traugott and Huddleston, "Bootstrapping an Infrastructure", LISA '98 (not fetched; LISA '05 cites it). G8 state 3: installing from public docs is a cold-path provisioning problem.
4. Couch and Sun, "On the Algebraic Structure of Convergence", DSOM 2003 (already [7], uncited; abstract fetched, T42). The fixpoint loop in §5.1 and convergence on each device (G3). Couch's later closure and "aspects" work (not fetched) is also relevant.
5. Anderson, LCFG, and Anderson and Scobie, LISA 2002 (not fetched; the LCFG site search returned junk). This is the declarative prior art closest to the Site Model. Anderson is also an author of µPuppet [8]. G2 and G7.
6. Anderson, *System Configuration*, USENIX Short Topics #14 (not fetched). A survey of exactly the declarative-versus-imperative spectrum G7 asks to be challenged on.
7. Delaet, Joosen and Vanbrabant, "A survey of system configuration tools", LISA 2010 (a local copy is in the Bcfg2 source tree's `doc/papers/`, not reread). Its comparison framework fits the §2 tool choice.
8. Hummer, Rosenberg, Oliveira and Eilam, "Testing Idempotence for Infrastructure as Code", Middleware 2013, https://link.springer.com/chapter/10.1007/978-3-642-45065-5_19 (abstract fetched). Model-based testing of convergence "from arbitrary states". G4's "mechanically checked" and the canary tests.
9. Shambaugh, Weiss and Guha, "Rehearsal", PLDI 2016, https://arxiv.org/abs/1509.05100 (abstract fetched). A sound determinism and idempotence check for Puppet. This is the precedent for checking the compiler's output in G4, and an alternative to inferring ordering.
10. Weiss, Guha and Brun, "Tortoise: Interactive System Configuration Repair", ASE 2017 (not fetched). It turns manual fixes back into configuration. G1 (the user edits directly and the AI keeps the spec in step) and G9.
11. Rahman, Parnin and Williams, "The Seven Sins: Security Smells in Infrastructure as Code Scripts", ICSE 2019; Sharma, Fragkoulis and Spinellis, "Does Your Configuration Code Smell?", MSR 2016 (not fetched). Ready-made scanners and taxonomies for G4's "scanned for likely safety in several ways".
12. Pearce et al., "Asleep at the Keyboard?", IEEE S&P 2022; Perry et al., "Do Users Write More Insecure Code with AI Assistants?", CCS 2023 (not fetched). Evidence that AI-written code, and user trust in it, cuts against an unaided safety percentage. G4 and G6.
13. Kadavath et al., "Language Models (Mostly) Know What They Know", 2022 (not fetched). Calibration is the open question behind G4's "safety confidence out of 100%".
14. Pujar et al., Ansible Lightspeed / "Automated Code Generation for IT Automation", 2023 (not fetched). A shipped natural-language-to-YAML IaC assistant, which is G1's interaction model in production.
15. Samuel, Mathewson, Cappos and Dingledine, "Survivable Key Compromise in Software Update Systems", CCS 2010 (TUF; probably [26]'s paper, not fetched). Uptane (escar 2016) and in-toto (USENIX Security 2019) (not fetched) are the supply-chain layer for G3's "correct cryptographic handshake" between peers.
16. Lamb and Zacchiroli, "Reproducible Builds", IEEE Software 2022 (not fetched). Independent rebuilding of a signed release, which supports G3 peer acceptance.
17. Darcs/Pijul patch theory (Roundy; Mimram and Di Giusto, "A Categorical Theory of Patches", 2013) (not fetched). A commuting-patch model for G9's branch management without merging.
18. Burgess, "Computer Immunology", LISA '98 (not fetched). This is the origin of the self-sufficient convergent agent in G3. It is stronger support for §2.3 than the Promise Theory book.

## D. What I did not check

1. Still unread: the official ACM copy of [9] (the ACM DL page answers HTTP 403, a Cloudflare challenge; [9] was read in the author's JACM-layout copy on 2026-11-13). Read 2026-11-13: the [24] blog post at the cited URL (earlier failures were the web tool's, not the page's), and [29] through the tracker's public REST endpoint. Read only in part: [5] (first pages), [7], [8] and [14] (abstracts), [19] (repository listing, not module bodies). ncf/Rudder and the Puppet catalogue claims were not checked.
2. Round 1's docs.bcfg2.org failures were https; the site works over plain http. docs.cfengine.com works with markdown output. Both are now checked (T3-T9, T15, T18, T23, T28, T58). The https `docs.bcfg2.org` link in guide §4 was not retried.
3. The single YAML-over-JSON case in [16] was not read. The Promise Theory book [6] and Srivatsa [28] were read in full on 2026-11-13.
4. The guide's "Further reading" list (G:1649-1672) was not checked link by link.
5. Paper sections outside the Bcfg2, AI-literature and related-work passages were read only where they cite a source.

Sources consulted: Bcfg2 CLUSTER03, LISA '05, LISA '06, the 2008 booklet (local PDFs plus the USENIX LISA PDFs), Bcfg2 GitHub docs (bcfg2-info, Packages, papers appendix), docs.bcfg2.org 1.3.6 (bcfg2-info, Actions, altsrc, Deps, Packages, Bundler, Git, client modes, getting started), Pay As You Go (archive.org), docs.cfengine.com (client-server communication, Community install, 3.21 Augments), *Learning CFEngine* ch. 3 (Basic Memory `books`), the TUF spec, the cdktf, flux2, nix-darwin and cdk8s repositories, nixpkgs `systemd.nix`, the CNCF Flux page, the 2017 Weaveworks GitOps post (archive.org), the balena offline-updates docs, the Promise Theory page, Burgess 1995 (USENIX PDF), Couch and Sun (Springer), µPuppet (DROPS), region logic (Semantic Scholar metadata), Tratt's post, Kleppmann et al. (author PDF), Dolstra's thesis, the arXiv abstracts or full text of [11], [13], [14], [15], [16], [17] and [28], the IaC-Eval NeurIPS page, Hummer 2013 (Springer) and Rehearsal (arXiv).
Last search run: in round 2, firecrawl search for the balena post returned unrelated results except the balena docs page, and a search on the origin of "GitOps" returned snippets only (not used); direct scrapes were used for everything cited. Round 1: searches for Traugott, Hummer, LCFG and Rehearsal returned only junk results, and the USENIX LISA 2002 HTML was not fetched.

## Withdrawn after checking

None. The independent check refuted no item in this report.
