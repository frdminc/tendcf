# tendcf goal definition (agreed 2026-11-13)

Status: agreed between djbclark and the reviewing session on 2026-11-13, in an
eight-question walk; amended by the operator's rulings of 2026-11-14 (see
"Later rulings" below). This file is new. No original document was changed. The
review documents beside it measure everything against paragraphs G1 to G9.

Base commit for every anchor in this directory: `eefea3c` (master).

## The goal

**G1. Aim.** tendcf is free software that gives people control of their own
computing devices as they see fit. It is a configuration management system that
other people adopt. It is used through an AI or directly at the code level,
whichever the user prefers at any moment. Through an AI, a person says what
they want; the AI writes it as configuration and explains or warns when a
request looks unwise. The first adopters are sysadmins who already share
configs in Nix. The long-run user is a person with no admin skill at all.

**G2. Authoring.** Config is written in the real Nix language, with
NixOS-style options, so existing NixOS and nix-darwin configs carry over.
Plain YAML/JSON sits beneath it as the data form Nix evaluates to, and can be
written by hand. What a person is shown reads clearly without manuals.

**G3. Shape.** Every device is self-sufficient: it converges on its own, there
is no control node, and it accepts updates from any other device that
completes the correct cryptographic handshake. "Server" means only a machine
that provides services to others, such as receiving and archiving logs and
monitoring. "Client" means a device that uses them. The architecture is not
changed by these words.

**G4. Safety.** Nothing changes a device except as an exact, mechanically
checked difference that the device's owner can see and refuse. Each difference
is also scanned for likely safety in several ways, AI among them. The owner is
shown a safety score from 0 to 100, set as a ceiling by mechanical checks that
AI review can lower but never raise, with an explanation of each part of it,
its measured hit rate once a test corpus exists, and the questionable code
highlighted more dramatically the less safe it looks. This is offered in a command-line mode and a TUI mode. The TUI is
built on a scaffold borrowed from another project.

**G5. Platforms, in order.**

1. macOS as server
2. Android as client
3. macOS as client
4. Linux as server
5. Linux as client

Android is the main differentiator: comprehensive configuration management
that works with Island/Insular profiles and with user-space ShizukuPlus, which
the operator believes nothing else offers.

**G6. Premise.** That AIs write the configuration is the premise of the
project. It is not a hypothesis the project sets out to test.

**G7. Instruments.** CFEngine, the CFEngine fork, the Site Model and the
compiler are instruments. They are open to challenge, and nothing about them
changes without the operator's ruling.

**G8. Finish line.** Three states. Each is reached in this order, but work toward state 3 may start once state 1 holds.

1. One of the operator's Macs and one of his Android devices converge from
   Nix-authored config, with updates accepted only after the cryptographic
   handshake and logs archived on the Mac.
2. The operator's whole fleet runs on tendcf and the `~/ops` suite is retired.
3. A person the operator has not helped installs it from the public docs with
   their own AI and keeps using it. From state 1 on, a clean machine with a
   fresh AI session that has only the public docs rehearses this in CI.

**G9. Later.** Free-software branch management, built as an extension of the
platform's existing patch patterns, so that non-technical users can maintain
forks of projects, or of plugins to projects, without knowing about merging,
rebasing or compiling.

Whether tendcf becomes a product is undecided. If it does, it stays free
software.

## Rulings behind it

Each row is one question and the operator's answer. Quoted text is his.

| # | Question | Answer |
|---|---|---|
| 1 | Primary aim | Adoptable tool. "we eventually want to get to the point that non-sysadmin users, even clueless people, could use the tool via only via AI, with the AI translating the user's wishes into action, and teaching the user if a request looks maybe bad" |
| 2 | First adopter | Nobody named yet. |
| 3 | CFEngine | Instrument, open to challenge. |
| 4 | Nix authoring | Real Nix first, YAML beneath. |
| 5 | AI-only use | Taken as given; no experiment asked for. |
| 6 | Platforms | "The first platforms should be MacOS as server and Android as client, followed by MacOS as client, followed by linux server, followed by linux client. Android is one of the most important pieces as it will be the major marketplace differentiator" |
| 6b | Server and client | "I am not trying to change the architecture; client and server are not entirely meaningful here as each device will be self-sufficient and able to take updates from any other device that uses the correct crytoographic handshake. So when I say server I am refering only to the machines that are a server for services like recieving and archiving logs and doing monitoring of other machines." |
| 7 | Finish line | The ladder of three states in G8. |
| 8 | Wording | Agreed, with two changes to the draft. G1: "it is used through an AI or at the code level depending on the user's preference at any point in time." G4: "the diffs are also scanned in various ways including using AI for likely safety, and the user gets to see safety confidence out of 100% as well as an explanation of why that percentage was choosen and the code that is questionable should be hilighted in increasingly dramatic ways depending on safety (we should borrow a TUI scaffold from another project, and have both command-line and TUI modes)." Framing: "focus on the user's freedom to control their own computing devices as they see fit." G9 added. |

## Later rulings (2026-11-14)

The goal text above changed in three places, all from the 2026-11-14 walk of
`14-synthesis-and-rulings.md` section B: the G4 figure sentence (B13 items 2
and 3, settled by B8), the G8 lead sentence (B13 item 4) and G8 item 3 (B13
item 5). Everything else below is a reading, recorded here so no reader has to
open the review to learn it.
Every quotation is the operator's chosen option; each is cited as
`operator ruling, 2026-11-14, <item>`.

1. **G3 and G8.1, the handshake (B1; B13 item 1).** B13 item 1: "1. Keep text; B1 is the reading". The goal text is unchanged. "The correct cryptographic handshake" means B1's content checks: B1: "1. Content checks; v0 first". An update is accepted only if it is signed by keys the device trusts, fresh, names this device, and carries the owner's approval; transport authentication decides only who may talk. First build: SSH-signature v0 (`ssh-keygen -Y` over goal-file bytes plus a counter); the map's 2-of-3 offline-root floor may lag until TUF.
2. **G4, the figure (B8; B13 items 2 and 3).** B13 items 2 and 3 are settled by B8: "1. Capped 0-100 score". The reading is wording 3: "score from 0 to 100", mechanical checks set a ceiling that AI review can lower but never raise, an explanation of each part, and a measured hit rate once a corpus exists (B13 wording 3, X-pm-03). G4 above carries it: the sentence beginning "The owner is shown" now reads as wording 3, with the highlighting clause kept (B13 wording 3 as written omits it; the operator's row-8 wording requires it). Ruled (operator ruling, 2026-11-14, PR 62 review Q5, record line L61): "1. Yes, keep it". This composite, wording 3 plus the kept highlighting clause, is the ruled sentence. (The two PR 62 reviewers had differed: one called it faithful, one asked for confirmation.) The operator's verbatim words stay in row 8 of the table. The cap values are B8 sub 1, "1. 09's table, top 95" (`03-response-map.md` M-§9-03). The owner-set auto-refuse floor is B8 sub 2, "1. Allowed, off by default" (`02-response-guide.md` G-§7-01). G4 stays whole in state 1: B8 sub 3, "1. Build order, not scope" (the CLI diff and `y/N` is built first, state 1 is declared only once score, explanation, highlighting and TUI land, and there is no "state 1.5"). The TUI scaffold is B12, "2. Borrow both freely; raise Python" (Toad and textual-diff-view; the review TUI becomes AGPL-3.0-only and moves to Python >=3.14).
3. **G5, platforms and "comprehensive" (B9; B13 item 6).** B9: "1. Keep G5; word public claim". G5 is unchanged. Public docs use "we know of no other tool that converges an owner's own unrooted phone, including its Island/Insular work profile, from a signed goal file, without MDM enrollment or root" and state the developer-verification terms (ADB exempt; advanced flow one-day wait; limited distribution 20 against 50 devices discrepancy). B13 item 6 is settled by B9.
4. **G2, "carry over" (B7; B13 item 7).** B7: "1. Importer + matching names": a one-shot importer for pure-data option families (it lists what it did not carry), plus tendcf option names matching nix-darwin and NixOS where the meaning is the same. No G2 text was proposed, so none changed (B13 item 7).
5. **G8, order and rehearsal (B13 items 4 and 5).** B13 item 4: "1. Adopt the clarification". B13 item 5: "1. Add the rehearsal sentence". Both are applied in G8 above.
6. **G3 and G8.1, the `monitor` role (B4 rider).** "1. State 2": state 1 needs only the log archive (G8.1).
7. **G8, Android and Mac in state 1 (B3, B6).** B3: "3. Termux CFEngine + thin Kotlin". B6: "1. Plain Mac, launchd by tendcf", with sub 1 "1. macOS VM on bigmac" (state 1's Mac is an Apple Silicon macOS VM, a client and not an always-on server, that is also the log-archive server while bigmac is awake). Details are in `14-synthesis-and-rulings.md` section B. B3's ruling is about trust, consent and Termux; the Android log and index afterwards is ruled separately (operator ruling, 2026-11-14, PR 62 review Q3, "1. Agent keeps log role"): "only" is about decisions; the thin Kotlin agent still writes the device JSONL and index as a support role; map and D18 stand.

## Where this differs from the documents at `eefea3c`

These are the differences the review starts from. Each is taken up in the
response documents.

1. **Platform order.** The documents follow the 2026-10-29 order: Linux first,
   Android deferred. G5 puts macOS and Android first and Linux fourth and
   fifth. Every live host today is Linux.
2. **Nix and YAML.** D12 makes them equal frontends. G2 puts Nix first.
3. **Primary aim.** The map says "the trust/consent layer is the point". G1
   makes adoption the aim and G4 makes see-and-refuse the safety mechanism.
4. **Safety scoring.** The 0 to 100 confidence, its explanation, graded
   highlighting and the TUI are new. No document describes them.
5. **Peer updates.** "Updates from any other device that completes the
   correct cryptographic handshake" is firmer than the documents' open
   transport questions.
6. **Servers.** Log archive and monitoring as services other devices use are
   not in the build order.
7. **Finish line.** No document states one.
8. **Branch management (G9).** New.
9. **AI authorship.** The paper lists it among open questions. G6 fixes it as
   the premise.
