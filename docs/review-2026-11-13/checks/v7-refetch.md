# v7 refetch: sources left unread by the first review, fetched 2026-11-13

## TOOLS STILL BROKEN

Working: firecrawl_search (but its ranking is poor: most title searches returned unrelated sites, so I located papers through direct URLs, Crossref and the author's own pages); firecrawl_scrape with `formats: ["markdown"]` on arxiv.org; firecrawl_scrape with `formats: ["query"]` (works, returns a short answer).

1. `firecrawl_scrape` with `formats: ["summary"]`, url `https://arxiv.org/abs/2404.13076` and url `https://no-color.org`: both returned "An error occurred. Please check your logs for more details." (Error IDs 01a1d5e5-a4d3-7129-8365-cdd15bac2bba and 01a1d5e6-bc6e-776c-a550-215f39744e55). Still broken.
2. `firecrawl_research_search_papers` (query on LLM self-preference, k=3), `firecrawl_research_inspect_paper` (`arxiv:2404.13076`) and `firecrawl_research_read_paper` (`arxiv:2404.13076`): all three fail with "Request failed with status code 404". The whole research family is down.
3. `firecrawl_scrape` markdown of `https://www.gnu.org/licenses/gpl-3.0.html` and of `.../gpl-3.0.txt`: no response for 300 s, aborted, twice (one call ran alongside others; the second ran alone). Direct curl to gnu.org: HTTP 403; urllib: connection reset. Not used further.
4. `firecrawl_scrape` of `dl.acm.org/doi/10.1145/2485982`, `/doi/pdf/...`, `/doi/fullHtml/...` (also with `proxy: stealth`), the citeseerx PDF URLs and `blog.balena.io/...`: "All scraping engines failed" (or a Wayback 404). The balena page itself is fine: a direct fetch returned HTTP 200.
5. Library route (documented in the research skill: EZproxy prefix in `RESEARCH_PROXY_URL`, used through `research_check.py fetch ... --via-proxy`): works for Springer (Burgess 2005: via-proxy HTTP 200 PDF). For ACM it fails: the proxy sends the request on to dl.acm.org, which answers HTTP 403 "Just a moment..." (Cloudflare challenge), with the skill's client and with a browser user agent and a cookie jar. So the official ACM copy of the Banerjee paper stays unfetched; the author's JACM-layout copy on the author's institute site was used instead. Also note the skill's documented new name `RESEARCH_EZPROXY_PREFIX` is unset in this shell; only the old name is set.
6. web.archive.org returned HTTP 429 (rate limit) on one request.

## QUESTIONS FOR THE OPERATOR

1. Google's own pages disagree on the limited-distribution cap (overview and FAQ: 20 devices; the guide dated 2026-10-28: 50). Plan on 20 (my default in R12/R15), or wait for Google to reconcile them?
2. Do you want the official ACM copy of the Banerjee paper chased through a real browser (Cloudflare blocks every scripted client), or is the author's JACM-layout copy enough for the citation?

Worklist size: 35 source groups (table rows below); 26 corrections.
Counts by verdict: confirmed 15, refuted 1, still unfetched 1, weakened 18.

## Table

| Item ID(s) and document | Source | Route used | Quote (25 words at most) | Verdict | Correction |
|---|---|---|---|---|---|
| T44; paper §3.1 L991 and refs [9] (01, 06) | Banerjee, Naumann, Rosenberg, J. ACM 60(3), Art. 18, 2013, DOI 10.1145/2485982; author copy in the JACM layout: software.imdea.org/~ab/Publications/lrgi1.pdf | ACM via library proxy: HTTP 403 Cloudflare 'Just a moment' (3 URL forms). Author copy fetched directly, pdftotext, 36k words, ACM Reference Format line matches | "heap-local reasoning about mutation and separation"; "facilitates heap-local reasoning about object invariants". Intro: global invariants are handled by factoring "parts as they are relevant" | weakened | R1 |
| T27; P-§2.3-02 / P-§2.3-s21 (01, 06), paper §2.3 L379-383 | Burgess and Bergstra, Promise Theory: Principles and Applications (book, 2014); markburgess.org/BookOfPromises.pdf, ch. 1 and 17 | Direct fetch, pdftotext, 104k words (full book) | "originally invented to discuss the issues surrounding this autonomous operation, and voluntary cooperation"; "It is not about protocol modeling" (ch. 17.2) | refuted (the claim 'specifically to rule out client-server protocols that push data to a controller') | R2 |
| P-§2.3-02 Finding and proposed text (01) | Burgess, An approach to understanding policy based on autonomy and voluntary cooperation, DSOM 2005, LNCS 3775, DOI 10.1007/11568285_9 | Library proxy (documented route, via-proxy HTTP 200 PDF from Springer), 5.2k words | "no external agent can tell it what to do, without its consent"; promises rebuild "client-server interactions, dependencies and access control" | weakened (the book and this paper support 'no other agent can impose a promise', not 'cannot be obliged'; Burgess 2005 does not rule out client-server) | R2 |
| P-§2.3-02 'Burgess 2005 papers are the formalising source' (01) | Book ch. 1.9 and 17.2 (as above) | Same fetch | "A different motivation for promises was introduced by Burgess in the context of distributed management [Bur05]"; importance "first realized in 2004" modelling CFEngine | weakened (Bur05 introduced the voluntary-cooperation motivation; the book is the later full formalisation) | R2 |
| T54; P-§2.3-s26 (06), paper §2.3 L396-398, ref [24] | balena blog, Offline Updates (2021-02-12): blog.balena.io/offline-updates-make-it-easier-to-update-balena-devices-without-the-internet/ | Direct fetch HTTP 200 (the cited URL works; the earlier failures were the web tool's, not the page's), 1.5k words | "all data on the device is wiped at this point, making this different from a typical software update process"; no mention of degradation tracking | confirmed (06's 'overstated' and its replacement text stand; the reference URL may stay) | none |
| X-safety-06 and Q3 item 4 (09) | Panickssery, Bowman, Feng, arXiv:2404.13076 | firecrawl scrape (markdown) of abs page; direct fetch of the PDF, 9.8k words | "LLMs such as GPT-4 and Llama 2 have non-trivial accuracy at distinguishing themselves"; tasks: CNN/DailyMail and XSUM summaries only | weakened ('likely biased toward approving' goes beyond summarisation results on GPT-4, GPT-3.5, Llama 2) | R3 |
| X-safety-06 (09) | arXiv:2606.03437, Large Language Models Are Overconfident in Their Own Responses (ACL 2026 Findings) | Direct fetch of abs page | "models assign up to 26% higher confidence to their own responses" | confirmed (open-weight models, QA benchmarks, confidence not approval) | none |
| Q4 item 1 (09) | Akhawe and Felt, USENIX Security 2013, sec13-paper_akhawe.pdf | Direct fetch of the USENIX PDF, 11.6k words | "users continued through a tenth of Mozilla Firefox's malware and phishing warnings"; "70.2% of Google Chrome's SSL warnings"; 25,405,944 impressions | confirmed | none |
| Q4 item 2 (09) | Felt et al., Improving SSL Warnings, CHI 2015, research.google.com/pubs/archive/43265.pdf | Direct fetch, 8.4k words | "We ultimately failed at our goal of a well-understood warning. However, nearly 30% more total users chose to remain safe" (body: 'nearly 30 percentage points') | confirmed (09's wording is the abstract's) | none |
| Q4 item 3 (09) | Anderson et al., CHI 2015, DOI 10.1145/2702123.2702322; Vance et al., CHI 2017, DOI 10.1145/3025453.3025896; Vance et al., MISQ 2018, DOI 10.25300/MISQ/2018/14124 | Crossref and Semantic Scholar metadata and abstract (ACM pages bot-walled); bodies not read | CHI 2017 abstract (Crossref): "a dramatic drop in attention throughout the workweek despite partial recovery between workdays" | weakened (CHI 2017 is Vance et al., not Anderson et al.; the other two confirmed by title and abstract) | R4 |
| Q4 automation-bias reference (09) | Goddard, Roudsari, Wyatt, JAMIA 2012, PMID 21685142 | NCBI efetch XML | "Automation bias (AB)--the tendency to over-rely on automation"; systematic review, 74 of 13,821 papers | confirmed | none |
| Accessibility item 4 (09) | no-color.org (NO_COLOR) | firecrawl scrape (query format) and direct fetch | "present and not an empty string (regardless of its value), prevents the addition of ANSI color"; page "Last updated: 2026-11-03"; FAQ: only color | confirmed (including that bold and underline are not covered) | none |
| Q5 GPLv3 §13 (09) | GPL-3.0 §13 and AGPL-3.0 §13 text; SPDX verbatim copies raw.githubusercontent.com/spdx/license-list-data/main/text/GPL-3.0-only.txt and AGPL-3.0-only.txt | gnu.org: curl HTTP 403, urllib connection reset, firecrawl scrape timed out twice at 300 s; web.archive.org HTTP 429. SPDX copy fetched | "the special requirements of the GNU Affero General Public License, section 13, concerning interaction through a network will apply to the combination as such" | weakened (compatibility confirmed; the network clause reaches the whole combination, not only 'the borrowed parts') | R5 |
| Toad on Termux, table and Not checked 5 (09) | OpenHCSDev/agent-comms pull 4339 (and 4333), via api.github.com | Direct API fetch (public) | "Native resolution completed: 91 packages in 23.39s"; "Full app install/import still running; not claimed complete." Merged 2026-11-08 | weakened (dependency resolution and a diff-widget build shown; Toad running on Termux is not shown) | R6 |
| Refs 14, 15 (09) | arXiv:2608.02672 (Security-First Evaluation of Text-to-Terraform); arXiv:2609.28488 (IaC-Guard-V) | Direct fetch of abs pages | 2608.02672: "Syntactic validity and security compliance are largely orthogonal"; 2609.28488: "all models achieve 100% syntactic validity, only 32-50% of single-shot repairs pass full verification" | confirmed (both exist and fit; listed but cited nowhere in 09's items; 2609.28488 shows 'Submitted 12 Aug 2026' under a 2609 id, an odd mismatch to recheck) | none |
| B3 apt (10) | apt.conf(5), manpages.debian.org/trixie/apt/apt.conf.5.en.html | Direct fetch | "prevents replay attacks over a long timescale"; "the feature depends on the correctness of the clock on the user system" | confirmed (Check-Date wording also matches) | none |
| E2 journald Seal= (10, X-trust-11) | journald.conf(5), freedesktop.org/software/systemd/man/latest/journald.conf.html (docs v262; 'Added in version 189') | Direct fetch | "and a sealing key is available (as created by journalctl(1)'s --setup-keys command)"; "may be used to protect journal files from unnoticed alteration" | weakened (enabled by default but inert without a sealing key) | R7 |
| Tailscale row, N4 (10) | tailscale/tailscale LICENSE; tailscale/tailscale-android LICENSE (raw.githubusercontent.com) | Direct fetch | "BSD 3-Clause License ... Copyright (c) 2020 Tailscale Inc & contributors." (android repo: BSD-style text) | confirmed (fills the 'not checked' in the licence cell) | R8 |
| iroh row, N3, item 5 (10) | n0-computer/iroh-ffi README; Maven Central computer.iroh:iroh 1.2.0 (pom, module, jar listing) | Direct fetch; jar listed with unzip -l only | README: "higher-level protocols not yet at 1.0 (`iroh-blobs`, `iroh-docs`, `iroh-gossip`) are out of scope". Jar: darwin-aarch64, linux-x86-64, linux-aarch64, win32-x86-64 libs; module says standard-jvm, JVM 21 | weakened ('via iroh-ffi; not verified on Android' hides that no Android build is published and blobs is excluded) | R9 |
| Nebula row (10) | DefinedNet/mobile_nebula README and repo listing; slackhq/nebula LICENSE | Direct fetch and GitHub contents API | Repo: "Brings nebula to mobile devices (iOS, Android)"; README links a Play Store listing. Root listing has no LICENSE file; nebula core LICENSE is MIT | weakened (Android client exists; its licence cell 'MIT' is the core's) | R10 |
| D1/D2, X-trust-05 Curve25519 (10) | source.android.com/docs/security/features/keystore; AOSP frameworks/base AndroidKeyStoreProvider.java at tags android-12.0.0_r1 and android-13.0.0_r1; developer.android.com/privacy-and-security/keystore | Direct fetch; gitiles ?format=TEXT | "Android 13 added v2 of the KeyMint HAL, which adds support for Curve25519 for both signing and key agreement." android-13 source registers ED25519 and XDH; android-12 does not | confirmed (app-level support exists from Android 13 in source; developer.android.com does not document it) | R11 |
| X-android-07 developer verification (07), blocks-goal | developer.android.com/developer-verification, /guides/faq, /guides/limited-distribution; foresightmobile.com/blog/android-developer-verification-2026; gist by the Termux maintainer | Direct fetch of all five | FAQ: "Apps installed using ADB won't require verification."; "Unregistered apps can only be installed or updated when the advanced flow is enabled or by using ADB"; "There is a one-time, one-day wait" | weakened (dates, regions, ADB exemption confirmed; the advanced-flow wait and the 20-versus-50 device conflict need stating) | R12 |
| X-android-07 Termux maintainer gist (07) | gist.github.com/agnostic-apollo/b8d8daa24cbdd216687a6bef53d417a6 | Direct fetch, 17.9k words | "adb install ... internally is same as the /system/bin/pm install command"; F-Droid cannot sign the dummy APK for Termux | confirmed (still an inference about Shizuku; Google's pages do not address shell installs) | none |
| Line 57 Dhizuku licence (07) | thejaustin/ShizukuPlus OPEN_SOURCE_LICENSES.md; iamr0s/Dhizuku LICENSE | GitHub contents API; raw LICENSE | ShizukuPlus lists Dhizuku as "Apache License 2.0"; Dhizuku LICENSE: "GNU GENERAL PUBLIC LICENSE Version 3" | weakened (question settled: ShizukuPlus mislabels it) | R13 |
| UAD-NG row (07, snippet only) | flatpark/flatpark pull 871; UAD-ng releases API | GitHub API | PR created 2026-10-26, merged 2026-10-28; packages UAD-ng 1.2.0; latest release v1.3.1 (2026-11-02) | weakened (date and version in the row are stale) | R14 |
| Prior-art line and D19 (13); line on developer verification (12) | Same Google pages as X-android-07 | Direct fetch | Overview page: "share apps with up to 20 devices without a government-issued ID or registration fee"; guide (2026-10-28): "up to 50 devices" | weakened (13 omits the 50 figure and the wait; 12's rollout text confirmed) | R15 |
| T59; ref [29]; 14 item 12 (06) | CFE-4715 on the public tracker, via REST (northerntech.atlassian.net/rest/api/2/issue/CFE-4715 and /rest/api/3/search/jql) | Anonymous GET; no login attempted. Browse page still renders empty; the REST API answers | Summary: "cf-agent: retain the --simulate changes chroot after a run"; status Rejected, resolution Won't Do; all 26 of CFE-4715..4740 resolved 2026-08-19 | confirmed (paper's 'upstream ... rejected all twenty-six tickets' matches the tracker) | R16 |
| T40; paper §3.2 L1130-1132, ref [28] (06) | Srivatsa et al., arXiv:2404.00227 (full text) | Direct fetch of PDF, 6.4k words | Reported metrics: "Exact Match, BLEU ... Ansible Aware ... Schema Correct"; Terraform: plan compared with a reference. No hit for 'idempot' | weakened ('textual similarity ... rather than semantic' is half right; schema and plan checks exist; idempotence is absent) | R17 |
| T48; P-§3.2-s25 (06) | Park, Zhou, D'Antoni, arXiv:2502.05111v2 (full text) | Direct fetch of PDF, 10.9k words | "17.71x faster at offline preprocessing than SynCode"; ">30 minutes" for other tools; 25-35 s on 353-520-rule grammars; no production claim | confirmed (06's replacement text is supported by the body, not only the abstract) | none |
| 12 line 171 and Not checked (GPLv3 Installation Information) | GPL-3.0 §6 (SPDX copy) | As Q5 | "the Corresponding Source conveyed under this section must be accompanied by the Installation Information" when object code is conveyed in a User Product and possession is transferred | weakened ('relevant to phones handed to others' is right only when the project hands over the device with the software) | R18 |
| 02 line 598 (Shizuku needs ADB after reboot) | Shizuku user guide, shizuku.rikka.app/guide/setup/ | Direct fetch | "Due to system limitations, the startup steps need to be performed again after each reboot." | confirmed (for the wireless-debugging start; root start differs) | R19 |
| 08 table: system-manager (08) | numtide/system-manager README | Direct fetch | "System manager is tested against Nix 2.32 and above installed via nix-installer." | weakened ('Nix (≥ 2.32)' reads as a requirement) | R20 |
| 08: FlakeHub fh apply, Guix 1.5.0, mcp-nixos, nix-on-droid (08) | docs.determinate.systems/flakehub/store-paths/; guix.gnu.org blog 1.5.0; GitHub API for utensils/mcp-nixos and nix-community/nix-on-droid | Direct fetch and API | "To unlock this feature, sign up for a paid plan."; Guix 1.5.0 "January 23, 2026"; mcp-nixos 885 stars, MIT; nix-on-droid 2,206 stars, MIT, commits 2026-10-26 and 2026-08-21 | confirmed (the Guix 'GNU/Linux and Hurd only' platform claim was not separately checked) | none |
| 08 nix-darwin-fixer (snippet only) | mrhenry/nix-darwin-fixer; NixOS/nix#11075 | GitHub API | Repo archived, last push 2024-04-16, 1 star, MIT-0; nix#11075 "add UID migration script for macOS Sequoia 15", closed 2024-07-10 | weakened ('a fixer LaunchDaemon exists' omits that it is archived and two years old) | R21 |
| 08 snix 'no drop-in binary' (snippet only) | snix.dev | Direct fetch of home page and /docs/ | Page says "Nix-compatible surface" and "Designed to be embedded"; the words 'drop-in' do not occur | still unfetched (the quoted phrase could not be located) | none |

## Corrections

Each correction names the document, the item, the exact old phrase and the exact new text. `/` separates two edits inside one correction.

**R1** — Paper §3.1 (06 T44); same sentence recurs at L1907 only as '[9]', no edit there
   Old: Banerjee, Naumann, and Rosenberg's region logic [9], which derives global heap invariants from purely local reasoning about mutation and separation.
   New: Banerjee, Naumann, and Rosenberg's region logic [9], which supports heap-local reasoning about mutation and separation, so that a global object invariant can be maintained by reasoning only about the part of the heap a command touches.

**R2a** — 01 P-§2.3-02 and 06 P-§2.3-s21 (one merged edit), proposed text; and the paper §2.3 L379-383 sentence it replaces
   Old: In Promise Theory, which underlies CFEngine, an agent can promise only its own behaviour and cannot be obliged by another [6].
   New: In Promise Theory, which was developed to describe CFEngine's decentralised mode of operation, an agent can promise only its own behaviour and no other agent can impose a promise on it [6].

**R2b** — 01 P-§2.3-02 Finding (c), last sentences
   Old: Burgess's 2005 autonomy papers are. The sources reviewer should check [6].
   New: Burgess's 2005 DSOM paper introduced the promise as a measure of voluntary cooperation, and the book says Promise Theory "is not about protocol modeling" (checked against the book and the 2005 paper, 2026-11-13). Burgess 2005 even builds client-server interactions from promises, so the theory does not rule them out.

**R2c** — 06 T27 verdict cell
   Old: unverifiable. The page describes "autonomous agencies" and "voluntary cooperation"; the "specifically to rule out" purpose is not stated there.
   New: refuted. The book (ch. 17.2) says Promise Theory was "originally invented to discuss the issues surrounding this autonomous operation, and voluntary cooperation" and "is not about protocol modeling"; Burgess 2005 builds client-server interactions out of promises.

**R3a** — 09 X-safety-06 Finding
   Old: it is likely biased toward approving it: LLM evaluators favour their own generations (arXiv 2404.13076),
   New: it may be biased toward approving it: LLM evaluators favour their own generations in news-summary tasks (arXiv 2404.13076; GPT-4, GPT-3.5 and Llama 2; code review was not tested),

**R3b** — 09 X-safety-06 Evidence, and Q3 item 4 last sentence
   Old: (not fetched by the checker; fetch it before merging)  /  The 2404.13076 citation was not fetched by the checker, so fetch it before merging (independently checked 2026-11-13: weakened, corrected).
   New: (abstract and full text read 2026-11-13)  /  [delete the sentence; arXiv 2404.13076 was fetched and read on 2026-11-13]

**R4** — 09 Q4 item 3
   Old: Snippet only:    Anderson et al., CHI 2015 (fMRI); Anderson et al., CHI 2017 (workweek);    Vance et al., MISQ 2018. All dl.acm.org, which firecrawl could not fetch.
   New: Anderson et al., CHI 2015 (fMRI study of polymorphic warnings); Vance et al., CHI 2017 (five-day workweek: "a dramatic drop in attention throughout the workweek despite partial recovery between workdays"); Vance et al., MISQ 2018 (longitudinal fMRI, eye tracking, field experiments). Titles, authors and the CHI 2017 abstract were checked through Crossref and Semantic Scholar on 2026-11-13; the paper bodies were not read.

**R5** — 09 Q5 recommendation paragraph
   Old: GPLv3 §13 allows combining with AGPLv3 code; this is from knowledge, because the gnu.org fetch timed out. Not checked: the independent checker did not fetch it either; fetch https://www.gnu.org/licenses/gpl-3.0.html §13 before the licence ruling. The combined program would carry AGPL's network clause for the borrowed parts.
   New: GPLv3 §13 allows combining with AGPLv3 code: the GPL terms continue for the GPL part, and "the special requirements of the GNU Affero General Public License, section 13, concerning interaction through a network will apply to the combination as such" (read 2026-11-13 in a verbatim copy of the licence text; gnu.org itself would not load). The combined program would therefore carry AGPL's network clause as a whole, not only for the borrowed parts.

**R6a** — 09 table, Toad row, Termux cell
   Old: snippet only: resolved natively via uv (OpenHCSDev/agent-comms#4339, 2026-11-08)
   New: merged PR OpenHCSDev/agent-comms#4339 (2026-11-08, read): uv resolved 91 packages natively on a phone and selected Toad and textual-diff-view; the diff widget's backend built on Android CPython 3.14; "Full app install/import still running; not claimed complete."

**R6b** — 09 Not checked item 5 and references item 27
   Old: The Toad on Termux claim is snippet    only.  /  Snippet only: OpenHCSDev/agent-comms#4339 (2026-11-08) and #4333;
   New: The Toad on Termux claim rests on one merged PR that reports dependency resolution only; Toad itself has not been shown running there.  /  OpenHCSDev/agent-comms#4339 (2026-11-08) and #4333 (read);

**R7** — 10 E2
   Old: (journald `Seal=`, "Forward Secure Sealing ... based on Seekable Sequential Key Generators" by Marson and Poettering,
   New: (journald `Seal=`: on by default but active only when a sealing key exists, created by `journalctl --setup-keys`; Forward Secure Sealing is "based on Seekable Sequential Key Generators" by Marson and Poettering and "may be used to protect journal files from unnoticed alteration",

**R8** — 10 table, Tailscale / Headscale row, licence cell; N4
   Old: client BSD-3 (not checked)  /  N4. Tailscale Android non-root mechanics and licence.
   New: client BSD-3-Clause (LICENSE of tailscale/tailscale; tailscale-android carries a BSD-style LICENSE), read 2026-11-13  /  N4. Tailscale Android non-root mechanics.

**R9a** — 10 table, iroh row, Android and Library cells
   Old: via iroh-ffi; not verified on Android here  /  Library: "dial keys instead"; iroh-blobs for BLAKE3 content-addressed transfer;
   New: via iroh-ffi, whose Kotlin package (computer.iroh:iroh 1.2.0) is a standard-JVM jar with desktop libraries only (macOS arm64, Linux x86-64 and arm64, Windows); no Android library or AAR is published, so Android needs its own build  /  Library: "dial keys instead"; iroh-blobs for BLAKE3 content-addressed transfer (not in iroh-ffi, whose README puts iroh-blobs, iroh-docs and iroh-gossip out of scope);

**R9b** — 10 Not checked N3 and item 5 ("Later")
   Old: N3. iroh on Android.  /  5. **Later:** embed iroh in the Kotlin agent and drop the sidecar.
   New: N3. iroh on Android: checked 2026-11-13; no published Android build.  /  5. **Later:** embed iroh in the Kotlin agent and drop the sidecar, if an Android build of iroh-ffi is made and the blob transfer is not needed from it.

**R10** — 10 table, Nebula row, licence cell
   Old: | MIT |
   New: | MIT (nebula core; the Mobile Nebula repository has no LICENSE file) |

**R11** — 10 D2 Finding (and X-trust-05)
   Old: KeyMint HAL v2 (Android 13) adds Curve25519 signing; whether a given device's TEE implements it is per device.
   New: KeyMint HAL v2 (Android 13) adds Curve25519 signing; whether a given device's TEE implements it is per device. The app-facing AndroidKeyStore provider registers `ED25519` and `XDH` key-pair generators in AOSP from android-13.0.0_r1 (source read); developer.android.com's Keystore and KeyGenParameterSpec pages do not document them.

**R12** — 07 X-android-07 Finding, last bullet and Evidence; 07 section 3 item 5 (limited distribution bullet)
   Old: register under limited distribution (up to 20 devices per Google's FAQ; the limited-distribution guide, updated 2026-10-28, says 50; confirm before relying on either)
   New: register under limited distribution (Google's overview page and FAQ say up to 20 devices; the dedicated guide, updated 2026-10-28, says 50; plan for 20 until Google reconciles them; free, no ID). Unregistered apps can be installed or updated only while the advanced flow is on or by ADB; turning the advanced flow on takes a one-time one-day wait, then biometric or PIN confirmation, and can be allowed for 7 days or indefinitely. ADB installs are not subject to the wait.

**R13** — 07 line 57 (Not checked by either agent)
   Old: Not checked by either agent: the licence question raised by ShizukuPlus listing Dhizuku as Apache 2.0 while the Dhizuku repo is GPL-3.
   New: Checked 2026-11-13: ShizukuPlus's OPEN_SOURCE_LICENSES.md lists Dhizuku as "Apache License 2.0", but Dhizuku's own LICENSE is GNU GPL version 3. The attribution is wrong; treat Dhizuku as GPL-3.0. Whether ShizukuPlus copies Dhizuku code, which would affect its own Apache-2.0 label, was not checked.

**R14** — 07 table, UAD-NG row
   Old: v1.2.0; Flatpak PR 2026-10-29 (snippet only, https://github.com/flatpark/flatpark/pull/871)
   New: latest release v1.3.1 (2026-11-02); Flatpark PR #871 opened 2026-10-26, merged 2026-10-28, packages 1.2.0 (https://github.com/flatpark/flatpark/pull/871, read)

**R15** — 13 prior-art line (1) and D19; 12 item 4 (developer verification)
   Old: a "limited distribution" account (up to 20 devices, no ID, no fee)
   New: a "limited distribution" account (up to 20 devices per Google's overview page and FAQ, 50 per its 2026-10-28 guide; no ID, no fee). D19 should add that the "advanced flow" has a one-day wait before it can be turned on.

**R16** — 06 T59 verdict cell; 14 item 12
   Old: unverifiable (needs a browser session or login)  /  the [29] Jira ticket (empty shell)
   New: confirmed. The browse page renders empty, but the tracker's public REST endpoint answers anonymously: CFE-4715 is a feature request, status Rejected, resolution Won't Do; all 26 tickets CFE-4715 to CFE-4740 were resolved on 2026-08-19  /  [delete: the [29] ticket was read]

**R17** — Paper §3.2 L1130-1132 (06 T40)
   Old: evaluated by textual similarity to a reference rather than by semantic or idempotence correctness [28]
   New: evaluated mostly against a reference solution (exact match, BLEU, schema checks, plan equality) rather than by running the result and checking idempotence [28]

**R18** — 12 line 171 and Not checked
   Old: GPLv3 Installation Information for User Products is relevant to phones handed to others but **was not checked**.  /  - GPLv3 Installation Information: not checked.
   New: GPLv3 §6 requires Installation Information only when object code is conveyed "in, or with, or specifically for use in, a User Product" in a transaction that transfers possession of that product (read 2026-11-13); software installed on a phone the household already owns is not that case, but a phone handed over with the software on it is.  /  [delete: checked]

**R19** — 02 line 598 (evidence sentence)
   Old: Shizuku's need for ADB after reboot is inferred from https://github.com/thejaustin/ShizukuPlus ("a privileged process started with adb or root"), not fetched in full.
   New: Shizuku's need for ADB after reboot comes from its own setup guide (https://shizuku.rikka.app/guide/setup/): for the wireless-debugging start, "the startup steps need to be performed again after each reboot"; a rooted start is different (read 2026-11-13).

**R20** — 08 table, system-manager row
   Old: Nix (≥ 2.32)
   New: Nix, tested against 2.32 and above (the README says "tested", not required)

**R21** — 08 item 1 under macOS (snippet only)
   Old: (a fixer LaunchDaemon exists: [nix-darwin-fixer](https://github.com/mrhenry/nix-darwin-fixer), snippet only)
   New: (a fixer LaunchDaemon exists but the repository is archived, last pushed 2024-04-16: [nix-darwin-fixer](https://github.com/mrhenry/nix-darwin-fixer), read)

## Still unfetched

1. Official ACM copy of Banerjee et al. (DOI 10.1145/2485982): dl.acm.org/doi/10.1145/2485982, /doi/pdf/..., /doi/fullHtml/..., doi.org, each through the library proxy (HTTP 403 Cloudflare), firecrawl markdown (all engines failed), firecrawl stealth proxy (failed). The author's copy carrying the ACM Reference Format line for J. ACM 60(3), Article 18 was read in full instead.
2. gnu.org GPL text itself: curl 403, urllib reset, firecrawl timeout twice, Wayback 429. Verbatim SPDX copies of GPL-3.0 and AGPL-3.0 were read instead; if the operator needs the gnu.org page itself, it must come from a browser.
3. snix 'no drop-in binary' (08 item 7): snix.dev home page and /docs/ fetched; the phrase is not there. Web search for it returned unrelated pages.
4. Bodies of Anderson et al. CHI 2015 and Vance et al. MISQ 2018 (ACM and MIS Quarterly pages are bot-walled; only Crossref and Semantic Scholar metadata, and for CHI 2017 the abstract, were read). Not needed for any item beyond R4.
5. Burgess's own 'Computer Immunology' (LISA 1998) and the other further-reading entries in 06 section C: see Not attempted.

## Not attempted

1. 06 section C further-reading list, items 2-17 (Traugott and Brown, Anderson LCFG, Tortoise, Seven Sins, Pearce, Perry, Kadavath, Pujar, Samuel et al., Uptane, in-toto, Lamb and Zacchiroli, Darcs/Pijul, Computer Immunology): none is cited as support for a blocks-goal or misleads item, so I skipped them.
2. 06's partly-read [5] Burgess 1995, [7] Couch and Sun, [8] uPuppet, [19]: their rows (T41-T43) are bibliographic and already marked accurate; no claim rests on their bodies.
3. 07: Sui, Flyve MDM, Obtainium, Canta, Tasker, Automate, GrapheneOS tooling, Fleet's Android GitOps specifics, the Termux Play build. 12: Radicle, Obtainium, quilt/gbp-pq/stgit/git-branchless, Homebrew taps, Arch ABS, Renovate, PortGPT's success definition. 11: the 'prior knowledge' dagger items. 03/04/05: Termux build feasibility and the other 'not checked' items that need a device or a live host.
4. 08: home-manager `home.services`, system-manager's docs/options.nix, nix-darwin README flakes wording, and the FlakeHub plan details beyond the one sentence checked.
5. 13 E2 'quarter upstream' count and 10 X-trust-12 recovery table: these need history or design review, not a fetch.
6. The Guix 'GNU/Linux and Hurd only' platform claim in 08 (date checked, platform list not).

Sources consulted: firecrawl search and scrape, Crossref, Semantic Scholar, NCBI efetch, GitHub APIs, the research skill's fetch script with the documented library proxy; sources listed in the table.

Last search run: none run after the last fetch; the author's JACM-layout copy of the Banerjee article stands in for the unreachable ACM page.
