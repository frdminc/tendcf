# tendcf goal definition (agreed 2026-11-13)

Status: agreed between djbclark and the reviewing session on 2026-11-13, in an
eight-question walk. This file is new. No original document was changed. The
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
shown a safety confidence out of 100%, an explanation of why that figure was
chosen, and the questionable code highlighted more dramatically the less safe
it looks. This is offered in a command-line mode and a TUI mode. The TUI is
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

**G8. Finish line.** Three states, in order:

1. One of the operator's Macs and one of his Android devices converge from
   Nix-authored config, with updates accepted only after the cryptographic
   handshake and logs archived on the Mac.
2. The operator's whole fleet runs on tendcf and the `~/ops` suite is retired.
3. A person the operator has not helped installs it from the public docs with
   their own AI and keeps using it.

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
