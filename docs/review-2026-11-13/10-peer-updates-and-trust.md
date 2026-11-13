# 10: G3 review: peer updates, the cryptographic handshake, and trust

Base commit: eefea3c

How this was produced: one researching agent (Claude Opus), then an independent checking agent that fetched the cited sources and tried to refute each claim; nothing was executed.

Items by Weight after corrections: blocks-goal 5, misleads 3, improves 4, nit 0 (12 response items; none withdrawn).

Reviewer slice `p2-trust`, 2026-11-13, base `eefea3c`. Read-only; no repository file changed.

Sources consulted: shared `mcp__firecrawl__*` only. Fetched (date of source in brackets): TUF spec v1.0.37 [last modified 2026-10-08], Uptane Standard 2.1.0 [undated page], Tailscale Tailnet Lock [last validated 2025-12-02], Android Keystore [updated 2026-10-23], Apple "Protecting keys with the Secure Enclave" [undated], syncthing-android [archived 2024-12-03], Syncthing-Fork (researchxxl) README [undated], iroh README [© 2025], Nebula README [undated], apt.conf(5) trixie [undated], Nix manual 2.35 conf-file [undated], journald.conf systemd 262 [undated], CHAINIAC USENIX Security 2017 abstract [2017-08], gittuf README [undated], OSTree "Related projects" [undated]. `firecrawl_research_search_papers` returned HTTP 404 once (research tool only; web search and scrape kept working). Web search ranking was poor (off-topic hits), so most evidence is from direct scrapes.

Local sources read: goal definition; README format; review digest; map §9 preamble, §9.1, §9.4, §9.10, §9.11, §10, §11; guide §1, signing block (lines 547-566), §17, §20; validate proposal §3 and "does not yet guarantee"; `schema/approval-record.schema.json`, `schema/goal-file.schema.json` (key patterns).

## A. What the handshake must establish

A1. **Two layers, different jobs.**

| Layer | What it is | Covers | Does not cover |
|---|---|---|---|
| Transport authentication | Mutual key handshake between two devices (Noise, TLS, WireGuard, QUIC) | Confidentiality of goal files and logs in transit; who may open a channel (DoS, spam, metadata privacy); knowing which peer sent which log segment | Anything about whether the bytes should be applied. A legitimate peer that is compromised passes it. |
| Content authentication | Signatures on TUF metadata, the goal file (as a target) and the approval record, checked by the receiving device | Authorship, freshness, binding to this device, owner consent, independence from the relay | Confidentiality; availability (a relay can still withhold, which is a freeze) |

A2. **Properties the content layer must prove** (the device checks each, in this order, before computing the diff):

1. *Authorship.* The release metadata chains to the root this device enrolled at first run, and the goal file is a target signed by a threshold of the current targets keys (TUF §5.3-5.6; map §9.11).
2. *Not older.* Every metadata version and the goal file's release version are at or above the device's persisted high-water (TUF: "An attacker cannot trick clients into installing software that is older than that which the client previously knew to be available", https://theupdateframework.github.io/specification/latest/).
3. *Not stale.* Timestamp, snapshot and targets metadata are unexpired against the device clock; an expired set is reported as a possible freeze (TUF steps 5.4.4, 5.5.6, 5.6.5, same URL).
4. *Consistent.* The metadata set existed together (TUF "mix-and-match").
5. *For this device.* The goal file's `host` equals this device's own public key (map §9.1; `schema/goal-file.schema.json:16`).
6. *Approved by this device's owner.* An approval record for exactly this baseline-to-proposed pair, with a device-issued nonce and a higher `approval_seq`, signed by a key the owner holds and the release path cannot replace (map §9.1, §17 of the guide).
7. *Relay irrelevant.* None of 1-6 depends on who delivered the bytes. The relaying peer's transport identity decides only whether to talk to it.

A3. **Is "any device that passes the handshake may deliver" safe?** Yes, if delivery means courier and 1-6 are enforced on content: this is TUF's mirror model ("A repository mirror cannot prevent updates from good mirrors", TUF spec §1.5.2) and the validate proposal's option 2, which already treats the spool as untrusted and verifies signatures "before parsing anything else" (`docs/architecture/tendcf-validate-proposal-2026-11-03.md:466-474`). The residual risk is freeze: a peer that is the only route can withhold. It is bounded by metadata expiry, not prevented (independently checked 2026-11-13: confirmed).

A4. **If trust rests on the handshake alone:** every device holding a transport key becomes root on every other device, which is the full mesh that map §10 rejects ("not tenable once devices belong to more than one person", `architecture-DEFINITIVE-v3.md:926-930`). A lost phone with a mesh key could push arbitrary config. There is no rollback or freeze protection, no per-device binding, and no consent. And the mesh's own key distributor becomes the trust root: Tailscale's docs say that without Tailnet Lock, "If Tailscale were malicious, and stealthily inserted new nodes into your network, then Tailscale could send or receive traffic to your existing nodes" (https://tailscale.com/kb/1226/tailnet-lock, validated 2025-12-02; independently checked 2026-11-13: confirmed).

A5. **The literal G3 wording can be misread as putting trust in the transport layer.** G3 ends "The architecture is not changed by these words", and the owner's ruling (6b) says the same. The architecture already accepts content by TUF signature and approval record (map §9.11, §10). The intended reading is probably that the handshake is those content checks; the owner should confirm. Read alone, "accepts updates from any other device that completes the correct cryptographic handshake" reads as transport-gated acceptance, and G8.1 repeats it ("updates accepted only after the cryptographic handshake"). See X-trust-01 (independently checked 2026-11-13: weakened, corrected).

## B. Prior art and the smallest sound subset

B1. **TUF** (spec 1.0.37, 2026-10-08). Roles: root, targets, snapshot, timestamp, with delegations. Clients must persist root, timestamp and snapshot, and walk the root chain one version at a time. "the expiration of the new (intermediate) root metadata file does not matter yet", so an old client can catch up through expired intermediate roots. After key rotation the client deletes trusted timestamp and snapshot, to recover from fast-forward attacks (step 5.3.11). Freeze is bounded: "freeze attacks are limited by the expiration time of the latest root metadata available to the client". URL above (independently checked 2026-11-13: confirmed).

B2. **Uptane** 2.1.0 (https://uptane.org/docs/latest/standard/uptane-standard). There are two repositories. The Image repository is offline-signed. The Director "instructs ECUs as to which images will be installed by producing signed metadata on demand ... mostly controlled by automated, online processes". Both must match. A per-image release counter "can be used to prevent rollback attacks even in cases where the Director repository is compromised", and a hardware identifier ensures "an ECU cannot be ordered to install an incompatible image, even in cases where the Director repository is compromised". "ECUs SHALL have a secure source of time." ECU version reports carry a nonce or counter against replay. **Mapping:** tendcf's per-host goal file plays the Director's part (per device, made by the operator's tooling). The independent second signature has to come from somewhere the Director cannot reach, and the device-held approval key is that place. Shipped composition: Torizon OS is "libostree + Aktualizr", an Uptane client over OSTree (https://ostreedev.github.io/ostree/related-projects/). In Uptane the second, independent signer is the OEM's Image repository, "primarily controlled by human actors". Using the owner's approval key as that second signature is an analogy, not Uptane's design. (Independently checked 2026-11-13: confirmed; analogy note added.)

B3. **apt** (https://manpages.debian.org/trixie/apt/apt.conf.5.en.html). `Check-Valid-Until` "prevents replay attacks over a long timescale ... but the feature depends on the correctness of the clock on the user system". `Check-Date` can disable all time checks when "the machine's time cannot be trusted". This is the apt lesson: freshness by expiry is only as good as the client clock.

B4. **Nix** (https://nix.dev/manual/nix/2.35/command-ref/conf-file). `require-sigs` defaults to true. Non-content-addressed paths need a signature by a key in `trusted-public-keys`, and "Content-addressed paths are inherently trustworthy". It authenticates store paths only. Which generation is newest is outside the signature, so Nix caching is no model for freshness or rollback (inferred from the documented scope).

B5. **gittuf** (https://github.com/gittuf/gittuf): TUF-style policy over a Git repository, "removes the forge as a single point of trust"; beta, Apache-2.0. It fits if releases travel as a Git repository. I did not check its offline-client behaviour.

B6. **CHAINIAC** (USENIX Security 2017, https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/nikitin): witness cosigning plus a skipchain "enabling arbitrarily out-of-date clients to efficiently validate updates and signing keys". The idea that matters for a six-month phone is the skipchain. Witness cosigning needs witnesses a household does not have. I read the abstract only.

B7. **Tailnet Lock** is the nearest shipped analogue of "a device-local trust root the coordinator cannot write": "even if Tailscale were malicious or Tailscale infrastructure hacked, attackers can't send or receive traffic in your tailnet". Its limits apply directly here: "You cannot use an Android device as a signing node", "Tailnet Lock keys are stored on the device. If the device is compromised, the key can be obtained", and enablement is TOFU (same URL; independently checked 2026-11-13: confirmed).

B8. **Not fetched, so background only and unverified here:** in-toto (layout and step attestations; this is the "two-party authoring review" guide §17 names), Sigstore/Rekor (needs online CA and log services, which is a poor fit for no-control-node), OSTree static deltas (commit signing; deltas are a bandwidth feature only), Radicle (Git P2P with signed refs; no Android client known to me).

B9. **Smallest sound subset for one or a few signers** (recommended):

1. `root`: offline, threshold 2-of-3, with **no root key on the Mac that compiles and signs** (answers map §9.11's first open question). For example: one hardware token, one paper or air-gapped copy, one held by a trusted second person or a safe.
2. `targets`: one key, on the Mac.
3. `snapshot` and `timestamp` combined into one online key on the Mac, re-signing short-expiry timestamps.
4. No `emergency` role in milestone 1. Root revokes; D42's "tighten without consent" rule still applies.
5. **The device-held approval key** is the second, independent signature. It is the Uptane Image-plus-Director agreement rule with the person as the second repository.

## C. Transport among a person's own devices

| Option | macOS | Android, no root | Linux | Both peers rarely online together | Licence | Embedding | Source |
|---|---|---|---|---|---|---|---|
| Syncthing (core) + Syncthing-Fork on Android | yes | yes; official app discontinued, "last release ... December 2024"; community Syncthing-Fork on F-Droid, under a single maintainer (the fork changed hands in 2025) | yes | Partly. Peer-to-peer only, so both must be up at the same moment; public relays handle NAT, not storage. A third always-on peer would be a store. | MPL-2.0 | None: a sidecar app syncing a spool folder. Android scoped storage access from the tendcf agent is unverified. | https://github.com/syncthing/syncthing-android ; https://github.com/Catfriend1/syncthing-android (redirects to researchxxl) |
| iroh | yes (Rust) | via iroh-ffi, whose Kotlin package (computer.iroh:iroh 1.2.0) is a standard-JVM jar with desktop libraries only (macOS arm64, Linux x86-64 and arm64, Windows); no Android library or AAR is published, so Android needs its own build | yes | Same: connection-oriented; relay fallback, no storage | MIT or Apache-2.0 | Library: "dial keys instead"; iroh-blobs for BLAKE3 content-addressed transfer (not in iroh-ffi, whose README puts iroh-blobs, iroh-docs and iroh-gossip out of scope); self-hostable relay | https://github.com/n0-computer/iroh |
| Nebula | yes | yes (Mobile Nebula) | yes | Needs some reachable node for discovery: a lighthouse ("Optional, but you really should") or a `static_host_map`. The lighthouse is not the trust root; the offline CA is. The CA has a 1-year default lifetime and host certificates expire with it, a hazard for a phone off for months. | MIT (nebula core; the Mobile Nebula repository has no LICENSE file) | Separate daemon or app | https://github.com/slackhq/nebula |
| Tailscale / Headscale | yes | yes (app) | yes | A coordination server (Tailscale's, or Headscale self-hosted) is needed to add nodes, refresh keys, change rules and revoke keys. Existing connections "mostly continue to function" while it is down, until keys expire. It is a control node in G3's sense for membership, not for traffic. Tailnet Lock cannot sign from Android. | client BSD-3-Clause (LICENSE of tailscale/tailscale; tailscale-android carries a BSD-style LICENSE), read 2026-11-13 | Separate app | https://tailscale.com/kb/1226/tailnet-lock |
| WireGuard mesh by hand | yes | yes (app) | yes | Static peers only; a moving phone has no endpoint without a coordinator | GPL-2.0 kernel / MIT tools (not checked) | Config only | not fetched |
| Secure Scuttlebutt, Briar, Yggdrasil, Radicle | not checked | not checked | not checked | SSB's signed append-only feeds suit logs | not checked | not checked | not fetched |
| LAN discovery + direct pull | yes | yes | yes | Works whenever both are on the home network | n/a | Small: tendcf's own fetch over the spool | inferred |
| Sneakernet (USB, `adb push`, file share) | yes | yes | yes | Fully; content is self-authenticating | n/a | None | inferred |

Table, independently checked 2026-11-13: the Syncthing row confirmed (single-maintainer note added); the Nebula and Tailscale rows weakened, corrected; the other rows were not checked; sources re-fetched 2026-11-13: the iroh and Nebula rows corrected, the Tailscale licence cell confirmed.

C1. **Recommended transport plan, Mac plus Android, milestone 1 (no always-on server):**

1. Define the **bundle**, not the transport. A bundle is a directory with TUF metadata, the per-host goal file and, going back, report rows and approval records. It is self-authenticating, and every carrier is untrusted (A2, A3).
2. **Phone pulls, Mac publishes.** The Mac writes bundles to an outbox. The phone fetches when it has a network and is awake, which suits Android's background limits better than push (inferred; Doze and WorkManager not fetched).
3. **Courier 1:** Syncthing, with a send-only folder on the Mac and a receive-only folder on the phone (Syncthing-Fork), plus the reverse pair for logs. Device IDs give transport authentication. Global discovery and relays can stay on, or be turned off for LAN-only.
4. **Courier 2:** manual sneakernet into the same spool. It is the recovery path when everything else fails.
5. **Later:** embed iroh in the Kotlin agent and drop the sidecar, if an Android build of iroh-ffi is made and the blob transfer is not needed from it. Do not adopt Tailscale, Headscale or Nebula as a trust element. If used, they are only an IP layer underneath.

## D. Device-local trust root

D1. **Hardware-backed keys that a publisher cannot read.** Android Keystore keeps key material out of the app process and can bind it to the TEE or StrongBox. StrongBox supports only "RSA 2048, AES 128 and 256, ECDSA, ECDH P-256, HMAC-SHA256, Triple DES". Keys can require "the user has been authenticated" per operation, through BiometricPrompt. Authorizations "can't be changed" after generation. "secure hardware doesn't usually enforce temporal validity interval authorizations, because it normally doesn't have an independent, secure real-time clock" (https://developer.android.com/privacy-and-security/keystore, 2026-10-23). The Secure Enclave holds no Curve25519/Ed25519 keys. Apple's key-protection page says it "Works only with NIST P-256 elliptic curve keys". The current CryptoKit `SecureEnclave` API also offers ML-KEM and ML-DSA, so P-256 is no longer the only option. The Secure Enclave "Can't encode preexisting keys", and supports a biometry access-control flag (https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave) (independently checked 2026-11-13: weakened, corrected).

D2. **Conflict with the schemas.** `host`, `advisor_key_map` keys and the approval record's `host` are all pinned to `^ed25519:[0-9a-f]{64}$` (`schema/approval-record.schema.json:15`, `schema/goal-file.schema.json:16,643`, `schema/goal-diff.schema.json:15`). The Secure Enclave and StrongBox cannot hold Ed25519 keys (D1). The Android TEE can: "Android 13 added v2 of the KeyMint HAL, which adds support for Curve25519 for both signing and key agreement" (https://source.android.com/docs/security/features/keystore, updated 2026-09-30); the app-facing AndroidKeyStore provider registers `ED25519` and `XDH` key-pair generators in AOSP from android-13.0.0_r1 (source read 2026-11-13), though developer.android.com does not document them. As written, then, the Mac (G5 platform 1) cannot keep its device or approval key in secure hardware at all. Android (platform 2) can keep it in the TEE on Android 13 and later, but never in StrongBox. See X-trust-05 (independently checked 2026-11-13: confirmed; `schema/goal-diff.schema.json:15` added).

D3. **What a phone-held, biometric-gated approval key changes.** It makes map §17's "advisor key ... plus a local human act" real for the phone. A compromised Mac (targets plus timestamp keys) can propose, freeze and read logs. On a phone at the `consented` tier (map §10; an `operator`-tier device needs no local yes), it cannot make the phone apply a change, because the approval needs a signature that only the phone's secure hardware makes, and only after the person authenticates on the phone. The phone shows the device-computed diff from its own baseline (map §9.1), so the Mac's briefing can mislead the person but cannot change what is approved. This answers guide §20 Q15 for Android in part. It does **not** cover: Android app updates to the tendcf agent itself, whose own APK signing key is a separate trust root outside TUF (inferred; map §12 not read); or a Mac that is both proposer and approver for itself (independently checked 2026-11-13: weakened, corrected).

D4. **Threshold or multi-party approval.** The approval record has room for one signature (`approval-record.schema.json`, single `signature`, "Exact encoding is residue"). n-of-m approval, for example the owner's phone plus a second household member, would need a list of signatures and a policy. That is not needed for milestone 1. Passkeys (WebAuthn) were not fetched. They are origin-bound authentication assertions, not general signing, so they are a weak fit (background, unverified).

## E. Logs and monitoring as services

E1. **Specify:** the log unit is the existing `device_convergence` report row (`schema/report-row.schema.json`; validate proposal 3(b)). Each device appends rows to a local hash-chained log, with each segment signed by the device key. Segments go into the outbound bundle (store and forward). The Mac verifies the chain and signature, archives, and writes an acknowledgement of the highest sequence into the next outbound bundle. Devices prune only acknowledged segments. At rest on the Mac, segments are encrypted to an archive key, because household device logs are personal data. The monitor is a **staleness query**, a dead-man's switch: "last row seen from device D older than N hours" and "D has not converged release R". Do not pull-scrape: sleeping phones look down.

E2. **Borrow whole:** forward-secure sealing for tamper evidence on Linux (journald `Seal=`: on by default but active only when a sealing key exists, created by `journalctl --setup-keys`; Forward Secure Sealing is "based on Seekable Sequential Key Generators" by Marson and Poettering and "may be used to protect journal files from unnoticed alteration", https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html, systemd 262), and `systemd-journal-remote` as a Linux receiver (same page). For the Mac receiver and dashboard I fetched nothing (Loki, VictoriaLogs, Uptime Kuma push monitors, Healthchecks). Pick one later. The spec above does not depend on the choice.

E3. **The open retention question is real:** about 288 rows a day per host at the 5-minute cf-execd default (`tendcf-validate-proposal-2026-11-03.md:492`). Ship deltas or summaries, not every row, when the phone is on metered data.

## F. Expiry and recovery

| Event | TUF | Uptane | Tailscale / Nebula | Recommended for tendcf |
|---|---|---|---|---|
| Phone off six months | Walks root N to N+k, ignoring intermediate expiry, then needs fresh timestamp metadata | Needs a secure time source | Nebula host certificates expire with the 1-year CA; Tailscale node keys expire (page mentions key expiry, details not fetched) | Expiry gates **installing**, never **converging** on the approved baseline. On wake: catch up the root chain, then fetch a fresh timestamp from the Mac. If unreachable, keep converging and report. Device clock: keep a "latest trusted time" high-water and refuse metadata whose expiry is earlier than it. The diff from a six-month-old baseline will be large (guide §20 Q10). |
| Lost targets or timestamp key | Root rotates it; clients drop cached timestamp and snapshot | Director keys are online and rotated by the OEM | n/a | Root (offline, not on the Mac) re-keys. |
| Lost root below threshold | Remaining threshold rotates | n/a | Tailnet Lock: 10 disablement secrets, "print ... and store them in a secure safe"; lost secrets mean "the tailnet cannot be recovered" | Retain every root version (DC-20). Write an out-of-band re-enrollment runbook. |
| Lost phone | n/a | n/a | Revoke the node | The phone's approval key dies with it. Revoke its identity key via the next release, which tightens and needs no consent (D42). The replacement enrolls fresh. |
| Compromised Mac | Attacker holds online keys: can freeze, cannot roll back past the high-water, cannot beat the root threshold | Uptane's two-repository rule limits a Director compromise | Tailnet Lock: revoke with co-signatures from other signing nodes | Attacker can sign goal files, freeze, read the log archive. Phone refuses without phone-side approval (D3). Recovery: root rotates targets and timestamp keys. The phone re-verifies its stored baseline and approval record (validate proposal 3(b) row 1). |

## Response items

### X-trust-01: replace "the correct cryptographic handshake" with stated properties

**Target:** `docs/review-2026-11-13/00-goal-definition.md` G3 "Shape", at the phrase "accepts updates from any other device that completes the correct cryptographic handshake"; and G8 item 1, "updates accepted only after the cryptographic handshake"
**Kind:** question
**Goal:** G3, G8
**Weight:** misleads
**Finding:** Read alone, "completes the correct cryptographic handshake" could mean a transport handshake, which would make every peer holding a transport key root on every device: the full mesh map §10 rejects. G3's last sentence and ruling 6b keep the architecture, under which the handshake is the content check. The safe reading is that any peer may *deliver*, and the device *accepts* only content that proves its own authorship, freshness, binding and owner approval. The independent checker's judgment on row 6b: the owner's verbatim answer ("I am not trying to change the architecture; ... able to take updates from any other device that uses the correct crytoographic handshake") is compatible with content signatures, because the architecture it keeps already authenticates content by TUF signature and authorises by approval record (map §9.11, §10). Reading G3 as transport-gated is therefore not a fair definitive reading; it is a possible misreading to raise with the owner.
**Evidence:** `docs/architecture/architecture-DEFINITIVE-v3.md:926-930`; TUF §1.5.2 mirror goals (https://theupdateframework.github.io/specification/latest/); Tailnet Lock (https://tailscale.com/kb/1226/tailnet-lock).
**Proposed text** (proposed wording for the operator's ruling, not a correction):

> it accepts updates delivered by any other device, and applies one only when the update itself proves, whoever carried it:
>
> 1. it is signed by keys this device trusts (which keys, and how a device enrols them, is the owner's ruling);
> 2. it is no older than anything this device has already seen, and recent enough to rule out a withheld newer release;
> 3. it names this device;
> 4. this device's owner approved exactly this change, with a key the owner holds and no release can replace.
>
> The connection between two devices is authenticated too, but that only decides who may talk, never what is applied.

(G8 item 1: replace "after the cryptographic handshake" with "after the checks G3 lists".)
**Merge:** needs the operator's ruling first (the goal text is agreed)
**Checked:** verified (read both texts and the cited sources); independently checked 2026-11-13: weakened, corrected

### X-trust-02: map §9.11 must say what expiry does to a sleeping device

**Target:** `docs/architecture/architecture-DEFINITIVE-v3.md` §9.11 "Signing and delivery", after the paragraph beginning "Signing: [TUF]"
**Kind:** add
**Goal:** G3
**Weight:** blocks-goal
**Finding:** §9.11 names a high-water mark but says nothing about metadata expiry, the device clock, or what an expired set does to convergence. A phone off for months will meet expired metadata. Without a rule it either refuses to converge (an outage) or ignores expiry (no freeze defence). Android secure hardware usually lacks a secure clock, and apt documents the same dependence.
**Evidence:** TUF steps 5.3.6, 5.3.10, 5.4.4 (URL above); https://developer.android.com/privacy-and-security/keystore ("normally doesn't have an independent, secure real-time clock"); https://manpages.debian.org/trixie/apt/apt.conf.5.en.html (`Check-Valid-Until`).
**Proposed text:**

> **Expiry and sleeping devices.** Expired metadata stops a device from *installing* a new goal file. It never stops the device converging on its current approved one. On waking, a device walks the root chain one version at a time (an intermediate root's expiry does not matter, TUF §5.3), then needs timestamp metadata newer than its clock. If none is reachable it keeps converging, records `freshness: unknown`, and reports a possible freeze. The device keeps a high-water of the latest time it has trusted and refuses metadata whose expiry is earlier than that, so a clock set back cannot revive old metadata.

**Merge:** insert after that paragraph
**Checked:** verified (sources fetched); behaviour proposed, not built; independently checked 2026-11-13: confirmed

### X-trust-03: delivery is a courier, not an authority

**Target:** map §9.11, the paragraph beginning "Push: any host holding `deploy-origin`"
**Kind:** reword
**Goal:** G3
**Weight:** misleads
**Finding:** "Push: any host holding `deploy-origin`" makes the pusher's role look like an authority. Under G3 there is no control node, and every peer may carry a bundle. The validate proposal already treats the spool as untrusted (option 2), and the map should state that as the rule. The proposed text also drops the `deploy-origin` push semantics for `operator` hosts and makes pull the default; those are design choices offered for the operator's ruling, not corrections.
**Evidence:** `architecture-DEFINITIVE-v3.md:917-920`; `docs/architecture/tendcf-validate-proposal-2026-11-03.md:466-474`.
**Proposed text:**

> Delivery: any device, or a person with a USB stick, may carry a release bundle into a device's spool. Carrying confers nothing. The device verifies every signature before it parses anything else, and a bundle from a stranger is exactly as good as one from the operator's Mac. Pull is the default: each device fetches on its own schedule when it has a network. Push is only a faster courier. On a `consented` device, neither installs anything without that device's approval record.

**Merge:** needs the operator's ruling first: it removes the `deploy-origin` push semantics for `operator` hosts and makes pull the default, which is map §9.11 design.
**Checked:** verified (read both texts); independently checked 2026-11-13: weakened (ruling), corrected: Merge made ruling-first

### X-trust-04: add a transport axis to the per-device trust table

**Target:** map §10 "Per-device trust (D38)", the table beginning "| Axis | Question | Default |"
**Kind:** add
**Goal:** G3
**Weight:** improves
**Finding:** The table separates release, consent and peer actions but has no row for "who may connect to me". That leaves room to read a transport key as release authority.
**Evidence:** `architecture-DEFINITIVE-v3.md:935-941`.
**Proposed text:**

> | **Transport** | Who may open a channel to me (deliver bundles, collect logs)? | Devices whose transport keys I enrolled. A transport key never signs a release or an approval. |

**Merge:** insert as the table's first row
**Checked:** verified (read table); independently checked 2026-11-13: confirmed

### X-trust-05: Ed25519-only key patterns block hardware-backed keys on macOS and Android

**Target:** map §9.1, the bullet beginning "The accept binds per DC-2"; and `schema/goal-file.schema.json` / `schema/approval-record.schema.json` key patterns
**Kind:** question
**Goal:** G3, G5
**Weight:** blocks-goal
**Finding:** `host` and `advisor_key_map` keys are pinned to `^ed25519:`. The Secure Enclave has no Ed25519 (it offers P-256 and, in current CryptoKit, ML-DSA), so the Mac (G5 platform 1) cannot keep its device or approval key in secure hardware. StrongBox lists ECDSA P-256 but not Ed25519. KeyMint HAL v2 (Android 13) adds Curve25519 signing; whether a given device's TEE implements it is per device. The app-facing AndroidKeyStore provider registers `ED25519` and `XDH` key-pair generators in AOSP from android-13.0.0_r1 (source read); developer.android.com's Keystore and KeyGenParameterSpec pages do not document them. An Ed25519-only format therefore rules out the Mac's enclave and every phone's StrongBox. A typed key prefix (`ecdsa-p256:` next to `ed25519:`) is a `schema_version` bump, which is a design ruling.
**Evidence:** `schema/approval-record.schema.json:15`; `schema/goal-file.schema.json:16,643`; `schema/goal-diff.schema.json:15`; https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave; https://developer.android.com/privacy-and-security/keystore (StrongBox algorithm list, 2026-10-23); https://source.android.com/docs/security/features/keystore (KeyMint v2 Curve25519, 2026-09-30).
**Proposed text:**

> Key identifiers are typed: `ed25519:` plus 64 hex, or `ecdsa-p256:` plus the 66-hex compressed point. A device identity key or advisor key held in the Secure Enclave or Android StrongBox is `ecdsa-p256`, because neither holds Ed25519 keys (ML-DSA in the Secure Enclave is a later option). An Android TEE key on Android 13 or later may be either.

**Merge:** needs the operator's ruling first (schema_version bump; two frontier reviews per the repo's standing rule)
**Checked:** verified (schema read; vendor docs fetched); independently checked 2026-11-13: weakened, corrected; sources re-fetched 2026-11-13: confirmed (AOSP source read; the app-level addition above)

### X-trust-06: the approval record must name its signer and algorithm

**Target:** map §9.1, same bullet, at "and `signature`, valid for exactly one target key"
**Kind:** add
**Goal:** G3
**Weight:** improves
**Finding:** The record carries `host` (the target) but not which key signed it or with what algorithm, and the signature encoding is "residue". The validator then has to try every enrolled advisor key, and key rotation (remove plus add in `advisor_key_map`) has no record of which key approved what.
**Evidence:** `schema/approval-record.schema.json` (`signature`: "Exact encoding is residue, not decided here"; no signer field).
**Proposed text:**

> The record also carries `signer` (the approving key's typed identifier, which MUST be present in the device's local trust root at verification time) and `sig_alg`. Both are inside the signed bytes.

**Merge:** insert after that sentence; needs the operator's ruling first (schema change)
**Checked:** verified (schema read); independently checked 2026-11-13: confirmed

### X-trust-07: the signing subset for one person, with root off the signing Mac

**Target:** map §9.11, the paragraph beginning "The 2-of-3 is a **floor**"
**Kind:** add
**Goal:** G3, G8
**Weight:** blocks-goal
**Finding:** §9.11 leaves open whether a 2-of-3 held on the compiling machine means anything. Answer it for milestone 1: it does not. Uptane's two-repository rule gives the model: an online signer is tolerable when a second, independently held signature must agree. For tendcf, that second signature is the device-held approval key. In Uptane the second, independent signer is the OEM's Image repository, "primarily controlled by human actors". Using the owner's approval key as that second signature is an analogy, not Uptane's design.
**Evidence:** `architecture-DEFINITIVE-v3.md:885-893`; https://uptane.org/docs/latest/standard/uptane-standard (release counter and hardware identifier "even in cases where the Director repository is compromised").
**Proposed text:**

> Milestone-1 key layout:
>
> - `root` is 2-of-3 with no root key on the Mac that compiles: one hardware token, one offline copy, one held apart.
> - `targets` is one key on the Mac.
> - `snapshot` and `timestamp` share one online key on the Mac.
> - No emergency role yet; root revokes.
>
> The Mac's keys can propose, freeze and re-sign. They cannot apply a change to a `consented` device, because that needs the device's own approval signature, the second signature Uptane gets from its Image repository.

**Merge:** insert after that paragraph; needs the operator's ruling first (deploy plan / key ceremony is a design ruling)
**Checked:** inferred (design); sources verified; independently checked 2026-11-13: confirmed; Uptane analogy note added

### X-trust-08: Q15 is partly answerable on Android

**Target:** `docs/paper/tendcf-architecture-guide.md` §20 question 15, at the sentence beginning "Whether a device-local trust root the release path cannot write"
**Kind:** add
**Goal:** G3, G5
**Weight:** improves
**Finding:** For the phone, a Keystore key generated on the device, non-exportable, StrongBox-backed where available and requiring user authentication per operation, is a device-local trust root the release path cannot write. StrongBox and the Secure Enclave need P-256; the TEE accepts Ed25519 from Android 13 (X-trust-05). macOS has the same shape through the Secure Enclave with a biometry flag. The agent's own APK update channel stays outside it.
**Evidence:** https://developer.android.com/privacy-and-security/keystore ("Once a key is generated or imported, its authorizations can't be changed"); Apple Secure Enclave page (URL above).
**Proposed text:**

> On Android and macOS, the narrowest version exists in the platform. An approval key generated in the Keystore (StrongBox where present) or the Secure Enclave cannot be exported, and can be bound to a fresh biometric or PIN check for every signature. No release can read it or sign with it. That makes "the current advisor key plus a local human act" a hardware property for approvals on those devices. It does not cover the policy the validator reads, nor the agent's own app-update channel.

**Merge:** insert after that sentence
**Checked:** verified (vendor docs); not built or tested; independently checked 2026-11-13: confirmed

### X-trust-09: guide §1's "no always-on central server" needs its freshness caveat

**Target:** guide §1 "What this is", at "no always-on central server that every device must reach"
**Kind:** reword
**Goal:** G3
**Weight:** misleads
**Finding:** With a TUF timestamp role, a device must reach a fresh timestamp signer to *install*, though not to converge. Saying so keeps §1 true under G3 and X-trust-02.
**Evidence:** guide `docs/paper/tendcf-architecture-guide.md:50-52`; TUF freeze checks (URL above).
**Proposed text:**

> and no always-on central server: a device keeps converging on what it last approved with no network at all, and needs only some route, even a USB stick, to a recently signed timestamp before it installs anything new.

**Merge:** replace that clause
**Checked:** verified (text read); independently checked 2026-11-13: confirmed

### X-trust-10: name the milestone-1 transport

**Target:** map §9.11, after the "Push:" paragraph (as reworded by X-trust-03)
**Kind:** add
**Goal:** G3, G8
**Weight:** blocks-goal
**Finding:** No document names a transport; G8.1 needs one for a Mac and a phone that is often asleep. A self-authenticating bundle makes the courier replaceable. Syncthing has maintained macOS, Linux and community Android builds today, and needs no tendcf code.
**Evidence:** https://github.com/syncthing/syncthing-android (discontinued, archived 2024-12-03); https://github.com/Catfriend1/syncthing-android (Syncthing-Fork, F-Droid, MPL-2.0); https://github.com/n0-computer/iroh.
**Proposed text:**

> Milestone-1 couriers: (1) Syncthing (Syncthing-Fork on Android), with a send-only bundle folder on the Mac and a receive-only one on each device, and the reverse pair for log segments. (2) A manual spool import for sneakernet. Neither is trusted (above). An embedded peer-to-peer library (iroh, MIT/Apache) may later replace the sidecar. Mesh VPNs (Tailscale, Headscale, Nebula) may carry IP underneath, but are never a trust element. A Tailscale/Headscale coordinator controls membership and key refresh (a control node for the network). A Nebula lighthouse only helps peers find each other, while its offline CA controls membership.

**Merge:** needs the operator's ruling first (tool choice; also the operator's toolchain-prompt rule)
**Checked:** verified (repos fetched); Syncthing-Fork access from the agent under Android scoped storage not checked; independently checked 2026-11-13: weakened, corrected

### X-trust-11: specify log shipping and monitoring

**Target:** map §8 "Local record (D18)", at its end (new subsection)
**Kind:** add
**Goal:** G3, G8
**Weight:** blocks-goal
**Finding:** G3 and G8.1 make log archiving on the Mac part of the first finish line, and no section specifies it. The design needs only a little: signed, chained segments of existing report rows, store-and-forward with acknowledgement, encryption at rest, and a staleness monitor.
**Evidence:** `docs/architecture/tendcf-validate-proposal-2026-11-03.md:492` (row writer, 288 rows a day); https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html (`Seal=`, FSS).
**Proposed text:**

> **Shipping the record.** Each device appends its report rows to a hash-chained local log and signs each segment with its device key. Segments travel in the outbound bundle by any courier. The archiving device verifies chain and signature, stores segments encrypted to the archive key, and acknowledges the highest sequence in its next bundle to that device. A device deletes only acknowledged segments. Monitoring is a staleness query over the archive: no row from a device for N hours, or a device not yet on release R. Nothing polls a device, because a sleeping phone is not a down phone. Linux hosts may also seal their journals (FSS).

**Merge:** insert as a new final subsection of §8
**Checked:** inferred (design); journald FSS verified; independently checked 2026-11-13: confirmed; sources re-fetched 2026-11-13: corrected (`Seal=` is inert without a sealing key)

### X-trust-12: recovery table for a lost key and a compromised Mac

**Target:** map §9.11, at "None of those is built."
**Kind:** add
**Goal:** G3
**Weight:** improves
**Finding:** DC-20's runbook is unwritten. Section F above gives the per-event behaviour from TUF, Uptane and Tailnet Lock. The map should carry the table so the first key ceremony is designed with recovery in view.
**Evidence:** Section F sources.
**Proposed text:** Section F's table, rows "Lost targets or timestamp key" to "Compromised Mac", "Recommended" column only.
**Merge:** needs the operator's ruling first (a key-recovery plan is a design ruling under the repo's standing rule); then insert after that sentence
**Checked:** not checked (the independent checker did not verify the recovery table line by line; that needs each Section F row checked against the TUF, Uptane and Tailnet Lock sources)

## Ideas and risks

1. **Risk: Android agent self-update bypasses TUF.** The APK's signing key is a separate root of trust. If it lives where the targets key lives, a compromised Mac ships a new validator. Keep it apart, and make the agent's digest a privileged hunk (it is, `goal-file.schema.json:655`). Inferred.
2. **Risk: Syncthing is peer-to-peer, not store-and-forward.** If the Mac sleeps whenever the phone is awake, nothing moves. Mitigation: the Mac stays on (it is the server), or sneakernet.
3. **Risk: clock.** Neither the phone's TEE nor apt's design gives a secure clock (D1, B3). The "latest trusted time" high-water (X-trust-02) is the cheap defence. Uptane requires a secure time source and tendcf has none.
4. **Idea: skipchain-style forward links** (CHAINIAC): each root version signs a pointer to the next, so a six-month phone verifies the chain in log steps. Worth it only if root rotations become frequent.
5. **Risk: consent fatigue after a long sleep.** A six-month diff is the "Forty-one entries" case (guide §20 Q10). Offer "show intermediate releases" as a display aid only.
6. **Idea: the approval round trip disappears for the phone.** If the person approves on the phone, the nonce, diff, briefing and signature never leave the device. Only the record goes back in the log bundle.
7. **Risk: Island/Insular work profiles.** Keystore keys are per app and per profile. An agent in the work profile and one in the personal profile are two identities. Not checked.
8. **Risk: Nebula's 1-year CA default** and Tailscale key expiry create silent outages for devices that sleep. Avoid them as trust elements.
9. **Idea: gittuf** if releases ever travel as a Git repository (G9 branch management): TUF policy over refs, forge-independent. Beta.
10. **Risk: the Mac as log archive is a privacy concentration.** A compromised Mac reads every device's history. Encrypting to an archive key held off the Mac (read on demand) limits it, at the cost of convenience.

## Not checked

N1. Whether the operator's own phone has StrongBox, and its Android version (TEE Ed25519 needs 13+).
N2. Syncthing-Fork release recency and scoped-storage access from another app.
N3. iroh on Android: checked 2026-11-13; no published Android build.
N4. Tailscale Android non-root mechanics.
N5. SSB, Briar, Yggdrasil, Radicle, in-toto, Sigstore, passkeys, OSTree static deltas: all unfetched.
N6. Mac-side log and monitoring tools: unfetched.
N7. Map §12 (Android), §13 build order.
N8. The CHAINIAC paper body (abstract only).
N9. Android Doze and WorkManager limits.

Last search run: run last, with firecrawl search "Android KeyMint Ed25519 Curve25519 support Keystore TEE Android 13", then a scrape of https://source.android.com/docs/security/features/keystore (2026-09-30). It found that KeyMint v2 (Android 13) supports Curve25519 signing in the TEE. That corrected D2 and X-trust-05: the Ed25519 conflict is total on the Mac's Secure Enclave and on StrongBox, not on the Android TEE.

## Withdrawn after checking

None. The independent checker refuted no claim in this report.
