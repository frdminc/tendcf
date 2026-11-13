# 07: Android landscape, constraints and design consequences

Base commit: eefea3c

How this was produced: one researching agent (Claude Opus) using web sources, then an independent checking agent that fetched primary sources and tried to refute each claim; no device was touched.

No phone, tablet or other device was touched, by either agent. Every on-device statement below comes from documentation, source code or the predecessor fleet's own records.

Items by Weight after corrections: blocks-goal 5, misleads 3, improves 7, nit 0 (15 items). None was withdrawn; two refuted facts were corrected in place (see "Withdrawn after checking").

Reviewer: Opus 5.5 `high`, read-only. Base for repo anchors: `eefea3c`. Note: the review worktree is at `c3ae530`, which adds only
`docs/review-2026-11-13/` on top of `eefea3c`. The goal definition and the README are cited from there.
Every other repo anchor was checked with `git show eefea3c:<file>`.

Sources consulted:
- this repo:
  - `00-goal-definition.md` G3–G8
  - `README.md` (item format)
  - `architecture-DEFINITIVE-v3.md` R1, R4, §6 adapter #2, §13 step 2, D22, D45
  - `linux-targets.md` header and §4
  - `research-answers-and-corrections-2026-08-13.md` §0
  - `bolt-choria-as-umbrella-2026-08-13.md:136–148`
  - GLOSSARY Android entries
- the predecessor product (the stayturgid repository):
  - AGENTS.md (issue #188)
  - `docs/notes/lessons-learned.md`
  - `tailscale-lockdown-interlock.md:109`
  - `android_apk.py:963–980`
  - `adb_shell.py:205`
  - `docs/research/text-based-android-config.md`
- the helper fork (the ShizukuTendCF repository's `README.md`)
- its issue #19, the fork newsletter, read with `gh`, read-only
- the external URLs cited below, all fetched on 2026-11-13 unless marked "snippet only"

## The differentiator claim, restated accurately

I found no free tool that converges an unrooted Android phone, owned by its user, from a declarative goal that also reaches into an Island or Insular work profile and needs no MDM enrollment. AMAPI, Fleet and Headwind are convergent but server-pushed and device-owner-based. App Manager, AppManagerNG, Hail and UAD-NG are imperative or one-shot. Shizuku, ShizukuPlus and Dhizuku are enablers, not configuration tools. This rests on the absence of a counter-example in my searches, not on proof, so the public claim should say "we know of no other tool that…" rather than "nothing else offers". Reaching into the work profile through shell works while the profile owner leaves debugging allowed, which is Island's default. Beyond that, it depends on the profile owner's API or on device-owner rights.

(From the independent check, 2026-11-13.)

### Maintenance of the projects the client would build on

As the independent check found them on 2026-11-13:

| Project | Maintained by | Licence | Last activity |
|---|---|---|---|
| ShizukuPlus ([repo](https://github.com/thejaustin/ShizukuPlus)) | thejaustin; built on thedjchi/Shizuku; not affiliated with RikkaApps | Apache 2.0 | Active: about 1.8k stars, 3,297 commits; README banner says the stable release is delayed and pre-releases come meanwhile |
| thedjchi/Shizuku ([repo](https://github.com/thedjchi/Shizuku)) | thedjchi | Apache-2.0 | Paused: README says "I'm pausing maintenance for the time being" |
| ShizukuTendCF (`frdminc/ShizukuTendCF`) | The owner; tracks thejaustin/ShizukuPlus (rebase plan in its `docs/SHIZUKUPLUS-REBASE-PLAN.md`) | Apache-2.0 (per this report; not re-checked) | The owner's fork |
| Dhizuku ([repo](https://github.com/iamr0s/Dhizuku)) | iamr0s | GPL-3 | Supports Android 6–17; F-Droid 2.13.0 added 2026-11-04 |
| Island ([repo](https://github.com/oasisfeng/island)) | oasisfeng | Apache-2.0 | No public commits since 2021-09-02 |
| Insular ([F-Droid](https://f-droid.org/packages/com.oasisfeng.island.fdroid/); source gitlab.com/secure-system/Insular, GitHub is a mirror) | proletarius101, single maintainer | Apache-2.0 | Last release 6.4.2 on 2025-08-07; commits resumed 2026-09-11 after a gap from 2025-07-30 |

Not checked by either agent: the licence question raised by ShizukuPlus listing Dhizuku as Apache 2.0 while the Dhizuku repo is GPL-3.

---

## 1. Landscape

Privilege tiers used below:
- **app**: an ordinary app UID
- **shell**: UID 2000, the ADB or Shizuku level
- **PO**: profile owner
- **DO**: device owner
- **root**

| Tool | What it configures | Privilege | Model | Licence | Activity (source date) |
|---|---|---|---|---|---|
| Island ([repo](https://github.com/oasisfeng/island)) | Work profile: clone, freeze, hide apps; Open API to third-party apps "with the standard runtime-permission" | PO (own profile); DO optional | Imperative UI plus API | Apache-2.0 (repo) | No public commits since 2021-09-02; Insular is the only maintained FOSS line, and it is thinly maintained |
| Insular ([repo](https://github.com/proletarius101/Insular), [docs](https://secure-system.gitlab.io/Insular/)) | Same, plus per-side VPN and USB prohibition. "Managed Mainland" controls the owner side when Insular is DO, set up manually; no new space after that | PO; DO for Mainland | Imperative | Apache-2.0 (F-Droid; source gitlab.com/secure-system/Insular, GitHub is a mirror) | Single maintainer; last release 6.4.2 on 2025-08-07 ([F-Droid](https://f-droid.org/packages/com.oasisfeng.island.fdroid/)); commits resumed 2026-09-11 after a gap from 2025-07-30 |
| Shelter ([F-Droid](https://f-droid.org/packages/net.typeblog.shelter/)) | Work profile, freeze | PO | Imperative | GPL-3 | Dormant: 1.9.1, 2023-12-12 |
| Shizuku / thedjchi fork ([repo](https://github.com/thedjchi/Shizuku)) | Gives apps a Binder at shell UID (`pm`, `appops`, `settings`, `cmd`); start-on-boot waits for Wi-Fi; watchdog | shell (or root) | Enabler, not a config tool | Apache-2.0 | thedjchi: "I'm pausing maintenance for the time being" (2026) |
| ShizukuPlus ([repo](https://github.com/thejaustin/ShizukuPlus)) | Shizuku plus Dhizuku mode (shares the DO binder), "Plus API", `plus` CLI in rish, local ADB proxy | shell; DO via Dhizuku; root for `/data/data` | Enabler | Apache-2.0 | 1.8k stars, 3,297 commits (2026-11-13); fork newsletter calls it "currently the closest to a clear, maintained general Shizuku successor" (frdminc/ShizukuTendCF#19, updated 2026-11-12); stable release delayed (README banner) |
| ShizukuTendCF (`frdminc/ShizukuTendCF`) | ShizukuPlus plus headless broadcasts, a trusted-signer allowlist, indefinite boot retry | as above | Enabler | Apache-2.0 | The owner's fork |
| Sui | Shizuku API via Magisk/KernelSU | root | Enabler | — | Not fetched |
| Dhizuku ([repo](https://github.com/iamr0s/Dhizuku)) | Shares DO with other apps; Android 6–17 | DO, set via ADB, ideally with no accounts; "via Shizuku can help avoid errors … account (experimental)" | Enabler | GPL-3.0 | F-Droid 2.13.0 added 2026-11-04 |
| rish | Shell at UID 2000 from Termux | shell | Imperative | Apache-2.0 | Ships with Shizuku |
| Android Management API ([intro](https://developers.google.com/android/management/introduction)) | Full policy model: work profile, fully managed, dedicated; enforced by Android Device Policy | DO/PO via Google's DPC | **Declarative policy**, server-pushed | Google service; EMMs must pass "Release your solution" | Current |
| Fleet Android MDM ([guide](https://fleetdm.com/guides/android-mdm-setup), 2026-10-09) | AMAPI through Fleet; BYOD work profile or wipe-and-QR fully managed; Play Protect certified only; needs Android Enterprise signup | DO/PO (Google) | Declarative; Fleet GitOps in general (Android GitOps specifics not checked) | MIT core (not re-checked) | Active |
| Headwind MDM ([site](https://h-mdm.com/), modified 2026-11-04) | Apps, settings, kiosk, logs; standalone, air-gapped; agent can be platform-signed | DO, from a server | Server-side profiles (convergent push) | Open-core ("Community … on GitHub") | Active |
| Flyve MDM | GLPI-based | DO | — | GPL | Not fetched; believed dead |
| Termux + Ansible (stayturgid) | Termux userland, APKs over ADB, settings over ADB | app (Termux UID) plus shell via ADB from the control node | Push, convergent-ish | — | Owner's fleet; last health check 2026-10-03 |
| Termux + CFEngine (stayturgid `device/termux/cfengine`) | Termux files, services (runit), commands | app (Termux UID) | **Convergent** | GPL-3 | In production on 3.27.1 (`research-answers…-2026-08-13.md` §0) |
| nix-on-droid | Nix userland in a proot | app | Declarative (userland only) | MIT | Ruled out by R4; local evaluation exists, not read |
| App Manager ([F-Droid](https://f-droid.org/packages/io.github.muntashirakon.AppManager/)) | Components, app ops, permissions, freeze, profiles | app/shell/root | Imperative profiles | GPL-3+ | 4.1.1, 2026-09-07 |
| AppManagerNG ([repo](https://github.com/SysAdminDoc/AppManagerNG)) | As above, plus "profiles preview the selected packages before freezing, uninstalling…", scheduled profiles, package-event triggers, "Encrypted snapshot bundles … to another device" | no-root/Shizuku/ADB/root | **Imperative profiles with a preview**; not convergent, not multi-device | GPL-3+ | v0.7.0, continuation since 2026-04-30 |
| Hail ([F-Droid](https://f-droid.org/packages/com.aistra.hail/)) | Freeze, hide, suspend | shell/DO/root | Imperative | GPL-3 | 1.11.0, 2026-08-27 |
| Canta | Debloat through Shizuku | shell | Imperative | — | F-Droid URL 404; not checked further |
| Obtainium | App updates from source URLs; config export | app | Declarative-ish list, not enforced | GPL-3 | Not fetched; stayturgid dropped it (PR #143) |
| Tasker / Automate | Event-driven automation; ADB-WiFi or Shizuku for secure settings | app/shell | Imperative | Proprietary | Not fetched |
| UAD-NG | Debloat lists over ADB from a PC; selection export/import | shell from a PC | Declarative list, one-shot | GPL-3 | v1.2.0; Flatpak PR 2026-10-29 (snippet only, https://github.com/flatpark/flatpark/pull/871) |
| GrapheneOS tooling | Per-profile isolation, Private Space | OS | — | — | Not checked |

Independently checked 2026-11-13: the ShizukuPlus, thedjchi, Dhizuku and Headwind rows confirmed; the Island row weakened, corrected; the Insular row's licence refuted (it is Apache-2.0, not GPL), corrected in place.

## 2. The differentiator claim: holds in part

**Interpretation confirmed.**
- "Island/inland" means Island and its FOSS fork Insular: work-profile apps that make themselves profile owner.
- "ShizukuPlus" is `thejaustin/ShizukuPlus`. It is a Shizuku fork based on `thedjchi/Shizuku`, adding Dhizuku mode and a Plus API. ShizukuTendCF is the owner's fork of it.

**What holds.** I found no tool that does all four of these for a stock, unrooted phone the owner keeps:
- declarative, convergent configuration from a goal file
- across several surfaces (packages, app ops, permissions, settings, Termux userland)
- through Shizuku rather than an MDM slot
- aware of the work profile

The nearest competitors and their gaps:
1. **AMAPI and Fleet.** Truly declarative, but:
   - they need Google, Play Protect certification and an Android Enterprise enrollment
   - they take the DO/PO slot
   - on BYOD they manage only the work profile, never the owner's personal side
   - turning Fleet off deletes the work profile
2. **Headwind MDM.** Server-pushed, needs DO, enterprise-shaped. G3 forbids a control node.
3. **AppManagerNG.** The closest app-level tool. It has a preview before applying, profiles, schedules and encrypted bundles that move to another device. It is imperative and single-device, with no goal file and no convergence.
4. **UAD-NG.** A declarative package list, but one-shot from a PC over ADB.
5. **stayturgid.** The owner's own predecessor. It does most of this today, but by Ansible push from a control node.

**What fails or needs qualifying.**
1. **"Comprehensive" is not reachable at shell UID.** Shell cannot:
   - read other apps' private data
   - act across the work-profile boundary when the profile owner sets `DISALLOW_DEBUGGING_FEATURES`, which Island sets only when its opt-in "ADB secure" toggle is on ("Shell does not have permission to access user X", [HackTricks](https://github.com/HackTricks-wiki/hacktricks/blob/master/src/mobile-pentesting/android-app-pentesting/shizuku-privileged-api.md))
   - set DPM-only policy

   stayturgid's work-profile install path (`adb install -r --user N`) has a timeout branch written for a possible confirmation dialog (`android_apk.py:955-981`); no observed failure is recorded.
2. **The Shizuku-class helper comes back after a reboot only through its own boot start.**
   - The privileged helper process dies at every reboot; without root it returns only through the helper's wireless-debugging boot start, which needs Wi-Fi (stock Shizuku needs a manual restart; ShizukuTendCF documents unattended boot start).
   - HackTricks says "A normal Shizuku session does not survive a reboot unless the device is rooted", and the same page says stored pairing keys let an app re-enable Wireless Debugging after boot without root.
   - The owner's fleet has one open boot failure, stayturgid #188, on a Fire OS tablet running an older thedjchi-based build; the documented recovery is peer start over external ADB. That failure is specific to Fire OS. A cold-reboot test remains a recommended check (X-android-08).
3. **Work-profile support depends on Island/Insular.** Island's Open API is the sanctioned route into the profile. The repo does not yet model either.

**Verdict.** The claim holds, as far as anyone searched, for "convergent, owner-controlled, work-profile-aware configuration at Shizuku privilege", with no MDM enrollment and no root. It rests on the absence of a counter-example, not on proof, so it should be worded "we know of no other tool that…" (see "The differentiator claim, restated accurately" above). Reaching into the work profile through shell works while the profile owner leaves debugging allowed, which is Island's default; beyond that it depends on the profile owner's API or on device-owner rights. The claim fails for "comprehensive". Each piece (MDM policy, Shizuku app tools, debloat lists, Termux CM) exists; we know of no tool that combines them. That combination is what to claim.

## 3. Hard constraints (2026)

1. **Shell UID scope** ([HackTricks](https://github.com/HackTricks-wiki/hacktricks/blob/master/src/mobile-pentesting/android-app-pentesting/shizuku-privileged-api.md)).
   - Can:
     - `pm install` (split APKs too), `pm grant`/`revoke`, `pm disable-user`, `pm uninstall --user 0`
     - `appops set`, `settings put` (system, secure, global)
     - `cmd connectivity` per-app network chains, cleared on reboot
     - `dumpsys deviceidle whitelist`, `am set-standby-bucket`
   - Cannot:
     - read `/data/user/0/<pkg>`
     - set DPM policy
     - cross into a work profile whose owner sets `DISALLOW_DEBUGGING_FEATURES` (Island: opt-in "ADB secure"; enterprise DPCs commonly set it)
2. **Persistence.**
   - Wireless-debugging sessions die on reboot. Some forks also lose them on lock (keepalive forks, #19).
   - thedjchi's start-on-boot waits for Wi-Fi and toggles debugging through WRITE_SECURE_SETTINGS.
   - USB or root is needed before first unlock (`rushiranpise/Shizuku-Next`, per #19).
3. **Phantom process killer and background limits.**
   - Android 12+ kills child processes of Termux.
   - Fix: `settings put global settings_enable_monitor_phantom_procs false`, which persists across reboot ([doc](https://github.com/aidanpark/openclaw-android/blob/aa454a22d9bac29106adbd19bc8638c0e7dd86c3/docs/disable-phantom-process-killer.md), 2026). Also battery-unrestricted and a wakelock.
   - Android 16: the JobScheduler runtime quota now applies to active buckets and to jobs running beside a foreground service ([A16](https://developer.android.com/about/versions/16/behavior-changes-all), updated 2026-10-28).
4. **Android 17** ([A17](https://developer.android.com/about/versions/17/behavior-changes-all), updated 2026-11-09).
   - "cross-profile loopback traffic is no longer permitted by default … regardless of what API level the app targets." Anything talking over localhost between the owner and work profiles breaks: an agent in user 0 and a peer in user 10, or the ShizukuPlus ADB proxy on 15555.
   - Also new: app memory limits, per-app keystore limits.
   - Forks report Shizuku breakage on 17: empty authorized-apps list, the hidden-API `deviceId` change (#19).
5. **Developer verification** ([page](https://developer.android.com/developer-verification), [FAQ](https://developer.android.com/developer-verification/guides/faq), [Foresight 2026-09-28](https://foresightmobile.com/blog/android-developer-verification-2026)).
   - Rollout:
     - Live from 2026-09-30 for participating stores in BR/ID/SG/TH on certified devices.
     - Global, and covering direct download, in 2027.
     - Non-GMS ROMs are unaffected.
   - ADB:
     - "Apps installed using ADB won't require verification."
     - "Unregistered apps can only be installed or updated when the advanced flow is enabled or by using ADB."
   - Limited distribution: up to 20 devices per Google's FAQ (the limited-distribution guide, https://developer.android.com/developer-verification/guides/limited-distribution, updated 2026-10-28, says 50; confirm before relying on either), with no ID and no fee.
   - Termux maintainer: `adb install` "internally is same as the `/system/bin/pm install` command", so Shizuku/rish installs are likely exempt. **Inference; Google has not confirmed it** ([gist](https://gist.github.com/agnostic-apollo/b8d8daa24cbdd216687a6bef53d417a6)). Independently checked 2026-11-13: confirmed that the ADB exemption is as quoted and that Google's pages do not address shell installs.
   - The same gist warns that F-Droid-signed Termux may be unable to register.
6. **Distribution.**
   - Play forbids the privilege model these tools need. Termux's Play build is not the main line; not re-checked this session.
   - F-Droid signs with its own keys, which collides with verification (gist above).
   - Termux F-Droid stable is 0.118.3 (May 2025) ([F-Droid](https://f-droid.org/packages/com.termux/)).
7. **Device-owner provisioning.**
   - Needs a device with no accounts, or a factory reset/QR flow.
   - Only one DPC at a time ("user could only use one Android DPC app at a time", Island README).
   - stayturgid reserves the DO slot for Island/Insular (`tailscale-lockdown-interlock.md:109`).
   - Insular Managed Mainland, Dhizuku and any MDM all compete for that one slot.
8. **CFEngine on Android.** `processes:` promises do not work, because toybox `ps` output does not parse (stayturgid `docs/notes/lessons-learned.md:234`).

## 4. Configurable surfaces against privilege

| Surface | app (Termux/agent) | shell (Shizuku) | PO (Island/Insular) | DO (Dhizuku/Mainland) | root |
|---|---|---|---|---|---|
| Termux files, packages, runit services | yes | yes | — | — | yes |
| Install, update or uninstall APKs (user 0) | prompt each time | yes, silent, verification-exempt (inference) | in profile | yes | yes |
| Install or freeze in the work profile (user 10) | no | yes, unless the profile owner sets `DISALLOW_DEBUGGING_FEATURES` (Island: opt-in 'ADB secure'; enterprise DPCs commonly set it) | **yes** (Island API) | yes | yes |
| Runtime permissions, app ops | no | yes | in profile | yes | yes |
| `settings` system/secure/global | system only, with WRITE_SETTINGS | yes | partial | yes | yes |
| Disable or hide packages | no | `disable-user`, `uninstall --user 0` | hide/suspend in profile | hide/suspend | yes |
| Per-app network block | VPN-app only | `cmd connectivity`, until reboot | per-profile VPN | always-on VPN, lockdown | iptables |
| Battery and standby exemptions | request | yes | — | yes | yes |
| User restrictions (USB, debugging, install sources) | no | no | in profile | **yes** | yes |
| Other apps' private data | no | no | no | no | yes |
| Boot-time start before unlock | no | no (Wi-Fi debugging) | — | yes (DPC is direct-boot aware; not checked) | yes |

## 5. Design consequences

1. **CFEngine in Termux plus a Kotlin helper, versus a native agent.**
   - Recommendation: keep CFEngine for Termux userland, which is already in production, and make the Android surfaces **CFEngine custom promise types**. Example types: `android_package`, `android_appop`, `android_setting`, `android_profile_app`.
   - Each would be a promise module served by tendcf-agent and the helper.
   - Custom promise types exist since 3.17. Modules that advertise `action_policy` support `--dry-run`/`--simulate` and must make "no changes" under `warn` ([docs](https://docs.cfengine.com/docs/lts/reference/promise-types/custom/)). That gives G4 one mechanically checked diff path across all platforms. G7 keeps CFEngine as the instrument, and D45's Kotlin agent becomes the module host, scheduler and log owner rather than a second convergence engine.
   - A native-only agent consuming the goal file would re-implement CFEngine's convergence semantics a second time, against the golden bytes.
2. **Update path for a phone that is asleep or offline.**
   - Pull, not listen. The agent fetches a signed goal bundle from any peer when an opportunity comes: charging, unmetered network, a WorkManager window, or Termux:Boot.
   - It verifies the bundle offline with the G3 handshake key set and keeps the last approved bundle.
   - Peers push opportunistically only when the phone is reachable. Never require an inbound port: cf-serverd in Termux dies with the process, and cross-profile loopback is blocked on 17.
   - Logs queue locally and upload to the Mac on the next contact (G8.1).
3. **G4 on a phone.**
   - CLI and TUI: run `tendcf review` in Termux.
   - Native: a notification opens an agent activity showing the projected diff, the 0–100 score with its reason, and highlighted risky lines, with Accept and Refuse.
   - A refusal is recorded and logged, and the bundle is held.
   - Because the device must be self-sufficient (G3), the default with no answer is to hold.
4. **Privilege degradation is a state, not an error.** When the helper is down after a reboot, the agent:
   - converges what the app tier can
   - marks shell-tier promises `not_kept: privilege-unavailable`
   - asks the owner to re-enable wireless debugging

---

## 6. Response items

### X-android-01: D22 still says Android is deferred

**Target:** `docs/architecture/architecture-DEFINITIVE-v3.md` §15 decision table, row "D22 | Platform sequence", at "Android deferred by the operator on 2026-10-29"
**Kind:** ruling-drift
**Goal:** G5
**Weight:** blocks-goal
**Finding:** G5 (2026-11-13) puts Android second, after macOS as server and before macOS as client and Linux. D22 still records Android as deferred behind Linux. A reader of the map builds Linux first.
**Evidence:** `architecture-DEFINITIVE-v3.md:1221` at `eefea3c`; `docs/review-2026-11-13/00-goal-definition.md` G5 (at `c3ae530`).
**Proposed text:**

> | D22 | Platform sequence | macOS as server, Android as client, macOS as client, Linux as server, Linux as client (operator, 2026-11-13, goal G5). Superseded: Android deferred (2026-10-29, [`linux-targets.md`](linux-targets.md)). |

**Merge:** needs the operator's ruling first (whether G5 supersedes the 2026-10-29 ruling, or orders goals but not build steps)
**Checked:** verified (read both files); independently checked 2026-11-13: confirmed

### X-android-02: linux-targets.md header calls the deferral current

**Target:** `docs/architecture/linux-targets.md` header quote, at "Status: current. Android/Termux is deferred"
**Kind:** ruling-drift
**Goal:** G5
**Weight:** misleads
**Finding:** The header says the deferral is current, and §4 "Consequences of deferring Android" builds on it. If X-android-01 is ruled, both go stale. See also X-android-03.
**Evidence:** `linux-targets.md:3`, `:42` at `eefea3c`.
**Proposed text:**

> Operator ruling, 2026-10-29; platform order superseded by goal G5 (2026-11-13): Android is the second platform, after macOS as server. Linux remains the reference for the build-order steps already started.

**Merge:** replace the header quote; needs X-android-01's ruling first
**Checked:** verified; independently checked 2026-11-13: confirmed

### X-android-03: build-order step 2 marked Deferred

**Target:** `architecture-DEFINITIVE-v3.md` §13 "Build order", row 2, at "**Deferred** (operator, 2026-10-29): Linux comes first"
**Kind:** ruling-drift
**Goal:** G5, G8.1
**Weight:** blocks-goal
**Finding:** G8.1, the first finish line, needs one Android device converging. Step 2 is marked deferred with no code. Step 3's inference also says "Android is deferred". See X-android-01.
**Evidence:** `architecture-DEFINITIVE-v3.md:1160` at `eefea3c`.
**Proposed text:**

> | 2 | Android under the Site Model; Termux types; agent owns JSONL+SQLite. **Next after step 1** (goal G5/G8.1, 2026-11-13). Not started as code: the schema carries a `termux` supervisor flavour and the `android-termux-services` fixture. `frdminc/ShizukuTendCF` is the R4 helper. |

**Merge:** needs X-android-01's ruling first
**Checked:** verified; independently checked 2026-11-13: confirmed

### X-android-04: name the helper and its privilege ceiling in R4

**Target:** `architecture-DEFINITIVE-v3.md` §2 R4, after "Nix may build zero-on-device-footprint artifacts only."
**Kind:** add
**Goal:** G5
**Weight:** improves
**Finding:**
- R4 says "a Shizuku-class helper" without naming the fork or saying what that tier can and cannot do.
- G5 names ShizukuPlus. The repo already has its fork, which runs at shell UID 2000.
- Shell cannot read other apps' data, set DPM policy or cross into a work profile whose owner sets `DISALLOW_DEBUGGING_FEATURES`. Island admits shell into its work profile by default; its opt-in "ADB secure" toggle sets that restriction.
- "No nix-on-droid" stays correct.

**Evidence:** `architecture-DEFINITIVE-v3.md:113–115`; https://github.com/thejaustin/ShizukuPlus; HackTricks Shizuku page (URL in §3).
**Proposed text:**

> The helper is `frdminc/ShizukuTendCF` (a fork of ShizukuPlus): shell UID 2000. That tier covers packages in user 0, permissions, app ops, settings and standby; it does not cover other apps' data, user restrictions or a work profile whose owner forbids shell. Device-owner powers come only through a Dhizuku-shared or Island/Insular owner (D-new, X-android-09).

**Merge:** insert after that sentence
**Checked:** verified against the sources named; work-profile behaviour of shell not tested on a device; independently checked 2026-11-13: weakened, corrected

### X-android-05: Site Model needs an Android user/profile dimension

**Target:** `architecture-DEFINITIVE-v3.md` §6 "**Android (adapter #2).**", after "Same Site Model vocabulary."
**Kind:** add
**Goal:** G5
**Weight:** blocks-goal
**Finding:**
- G5's differentiator is Island/Insular support, but the adapter has no notion of the Android user a promise targets: user 0, the work profile (user 10 on the owner's t2e), Private Space, Samsung Secure Folder.
- Nor does it record which app owns that profile.
- stayturgid counts only user 0 (`adb_shell.py:205`), and its work-profile install path (`adb install -r --user N`) anticipates a confirmation-dialog timeout (`android_apk.py:955-981`); no observed failure is recorded.

**Evidence:** files named above in the stayturgid repository; Island README "Open API" (https://github.com/oasisfeng/island).
**Proposed text:**

> Each Android promise names its target user (`owner`, `work`, `private`) and the work profile's owner app (`island`, `insular`, `none`). Promises into a work profile go through that owner's API when shell is refused there; an unreachable profile reports `not_kept`, never a silent skip.

**Merge:** needs the operator's ruling first (a new schema field: a `schema_version` bump, a design ruling with two frontier reviews); then insert after that sentence
**Checked:** inferred from stayturgid code and the Island README; not tested on a device; independently checked 2026-11-13: weakened, corrected

### X-android-06: Android 17 blocks cross-profile loopback

**Target:** `architecture-DEFINITIVE-v3.md` §6 adapter #2, after "Agent owns logs (§8)."
**Kind:** add
**Goal:** G5, G3
**Weight:** misleads
**Finding:**
- Android 17 blocks cross-profile loopback traffic by default, for all apps, whatever API level they target.
- Any design where the agent in the owner profile talks over localhost to a component in the work profile fails. So does a design that talks to the ShizukuPlus ADB proxy (port 15555) from another profile.
- It also argues against cf-serverd as an on-phone listener.

**Evidence:** https://developer.android.com/about/versions/17/behavior-changes-all (updated 2026-11-09).
**Proposed text:**

> No component listens on loopback for another Android user: Android 17 blocks cross-profile loopback by default. Owner–work communication uses the profile owner's cross-profile API or Binder through the helper.

**Merge:** insert after that sentence
**Checked:** verified (fetched); effect on ShizukuPlus's proxy inferred; independently checked 2026-11-13: confirmed

### X-android-07: developer verification and distribution

**Target:** `architecture-DEFINITIVE-v3.md` §6 adapter #2, after X-android-06's text
**Kind:** add
**Goal:** G5, G8.3
**Weight:** blocks-goal
**Finding:**
- tendcf-agent and the helper are sideloaded, unregistered apps.
- From 2026-09-30, verification applies to installs on certified devices in Brazil, Indonesia, Singapore and Thailand through participating stores (Play, Galaxy Store, HONOR, OPPO and others); it extends to all apps on certified devices in 2027.
- ADB installs are exempt. The Termux maintainer argues shell `pm install` is the same path, but Google has not confirmed that.
- G8.3, a stranger installing from the public docs, needs a stated install path: register under limited distribution (up to 20 devices per Google's FAQ; the limited-distribution guide, updated 2026-10-28, says 50; confirm before relying on either) or the full program, or rely on ADB/shell installs and the advanced flow.

**Evidence:** https://developer.android.com/developer-verification ; https://developer.android.com/developer-verification/guides/faq ; https://developer.android.com/developer-verification/guides/limited-distribution (2026-10-28) ; https://gist.github.com/agnostic-apollo/b8d8daa24cbdd216687a6bef53d417a6 ; https://foresightmobile.com/blog/android-developer-verification-2026 (2026-09-28).
**Proposed text:**

> Distribution: tendcf-agent and the helper are registered under Android developer verification before 2027; until then, and for updates, the helper installs with shell `pm install` (the ADB path, exempt from verification). A device whose installer is not exempt reports the update `not_kept`, not silently stale.

**Merge:** needs the operator's ruling first (whether to register, and under which account type)
**Checked:** verified (fetched); the shell-install exemption is an inference; independently checked 2026-11-13: weakened, corrected

### X-android-08: G8.1 needs a reboot-survival gate for the helper

**Target:** `architecture-DEFINITIVE-v3.md` §13 build order row 2 (as replaced by X-android-03)
**Kind:** add
**Goal:** G8.1
**Weight:** improves
**Finding:**
- The privileged helper process dies at every reboot. Without root it comes back only through the helper's own wireless-debugging boot start, which needs Wi-Fi and (stock Shizuku) a manual restart. ShizukuTendCF documents unattended boot start.
- Start-on-boot needs Wireless Debugging and Wi-Fi.
- The owner's fleet still has one open boot failure, stayturgid #188, on a Fire OS tablet with an older thedjchi-based build, recovered by peer start over external ADB. It is specific to Fire OS.
- A G8.1 claim that skips a reboot would overstate, so a cold-reboot test is a recommended check.

**Evidence:**
- stayturgid `AGENTS.md` (#188); stayturgid `docs/options.md:256-268` ("Fire-OS boot-path failure"), `STATUS.md:52-55`, `STATUS.md:112-114` and `docs/hacking.md:205-215` (read by the independent check)
- the ShizukuTendCF repository's `README.md` ("Start on boot: Available only with Wireless Debugging or Root mode")
- Shizuku setup guide, https://shizuku.rikka.app/guide/setup/ (stock Shizuku: wireless-debugging start redone "after each reboot")
- HackTricks Shizuku page

**Proposed text:**

> Step 2 is done when the device converges after a cold reboot: the app tier converges unattended, and the shell tier either resumes through the helper's boot start or reports `not_kept: privilege-unavailable` and asks the owner to re-enable wireless debugging.

**Merge:** needs the operator's ruling first (whether a cold-reboot test is part of step 2's done criterion); then insert into row 2, following X-android-03
**Checked:** verified (sources); boot behaviour of ShizukuTendCF not tested; independently checked 2026-11-13: weakened, corrected

### X-android-09: device-owner slot policy

**Target:** `architecture-DEFINITIVE-v3.md` §15 decisions, a new row after D45
**Kind:** question
**Goal:** G5, G4
**Weight:** improves
**Finding:**
- Android allows one DPC.
- The candidates for the slot are Insular Managed Mainland, Dhizuku (which shares DO through ShizukuPlus), or an MDM. AMAPI/Fleet would delete or own the work profile.
- stayturgid reserves the slot for Island/Insular.
- Setting DO needs an account-free device or a reset.
- The map has no ruling.

**Evidence:**
- Island README (one DPC at a time)
- https://github.com/iamr0s/Dhizuku
- stayturgid `tailscale-lockdown-interlock.md:109`
- https://fleetdm.com/guides/android-mdm-setup

**Proposed text:**

> | D-new | Android device-owner slot | Open: Island/Insular as profile owner of the work profile on every device; the device-owner slot is (a) unused, (b) Insular Managed Mainland, or (c) Dhizuku shared through the helper. tendcf never requires an MDM enrollment. |

**Merge:** needs the operator's ruling first (design ruling: two frontier reviews)
**Checked:** verified (sources); combinations not tested; independently checked 2026-11-13: confirmed, except "AMAPI/Fleet would delete or own the work profile", not checked (needs Google's AMAPI and Fleet documentation on what happens to an existing Island/Insular work profile at enrollment)

### X-android-10: Android surfaces as CFEngine custom promise types

**Target:** `architecture-DEFINITIVE-v3.md` §15 D45 row, after "(1) tendcf-agent is **Android-only**, written in Kotlin."
**Kind:** add
**Goal:** G4, G7
**Weight:** improves
**Finding:**
- D45 says the agent exists, but not how CFEngine reaches Android surfaces that need Binder at shell UID.
- CFEngine custom promise modules (3.17+) speak a JSON or line-based protocol over stdin/stdout.
- With the `action_policy` feature they honour `--dry-run`/`--simulate`, making no changes under `warn`.
- Hosting those modules in tendcf-agent keeps one convergence engine and one diff path for G4.

**Evidence:** https://docs.cfengine.com/docs/lts/reference/promise-types/custom/ (3.27 docs, fetched 2026-11-13).
**Proposed text:**

> Android surfaces are CFEngine custom promise types (`android_package`, `android_appop`, `android_setting`, `android_profile_app`) whose module is served by tendcf-agent through the helper, advertising `action_policy` so dry-run and simulate cover them.

**Merge:** insert after that sentence; needs the operator's ruling first (G7 instrument change)
**Checked:** protocol verified from docs; whether cf-agent in Termux can run a module that reaches the agent's Binder (it would be a `rish`- or socket-backed shim) is not tested; independently checked 2026-11-13: confirmed

### X-android-11: no `processes:` promises on Android

**Target:** `architecture-DEFINITIVE-v3.md` §6 adapter #2, after "Peer actions cover devices that need external ADB help."
**Kind:** add
**Goal:** G5
**Weight:** improves
**Finding:**
- On Android, toybox `ps` output is not parsable by CFEngine.
- `processes:` promises report "not found", and any `restart_class` hanging off one fires every run.
- The owner's fleet already works around this with `commands:`.

**Evidence:** stayturgid repository, `docs/notes/lessons-learned.md:234–249`.
**Proposed text:**

> The Android adapter never emits `processes:` promises (toybox `ps` is unparsable); liveness comes from the supervisor (`runit`/`sv status`) or the agent.

**Merge:** insert after that sentence
**Checked:** verified (read the lesson); CFEngine version on Termux 3.27.1 per stayturgid; independently checked 2026-11-13: confirmed

### X-android-12: background execution on the phone

**Target:** `architecture-DEFINITIVE-v3.md` §6 adapter #2, after X-android-11's text
**Kind:** add
**Goal:** G3, G8.1
**Weight:** misleads
**Finding:**
- Termux children die to the Android 12+ phantom process killer unless `settings_enable_monitor_phantom_procs` is false.
- Android 16 extends JobScheduler quotas to active buckets and to jobs alongside a foreground service.
- A `cf-execd` loop in Termux is the fragile path. The agent should schedule runs, and the helper should set the phantom-process setting as a promise.

**Evidence:**
- https://github.com/aidanpark/openclaw-android/blob/aa454a22d9bac29106adbd19bc8638c0e7dd86c3/docs/disable-phantom-process-killer.md
- https://developer.android.com/about/versions/16/behavior-changes-all (2026-10-28)
- `bolt-choria-as-umbrella-2026-08-13.md:136–148`

**Proposed text:**

> tendcf-agent schedules cf-agent runs (WorkManager on charge or unmetered network, plus a foreground service while running); the first promise the helper keeps is `settings_enable_monitor_phantom_procs=false` and the Termux battery exemption.

**Merge:** needs the operator's ruling first (the scheduling design: WorkManager plus a foreground service); then insert after X-android-11's text
**Checked:** sources verified; scheduling choice inferred; independently checked 2026-11-13: confirmed (the phantom-process source, a third-party doc, was not re-fetched)

### X-android-13: pull-on-wake signed updates

**Target:** `architecture-DEFINITIVE-v3.md` §6 adapter #2, at "Peer actions cover devices that need external ADB help."
**Kind:** add
**Goal:** G3, G8.1
**Weight:** improves
**Finding:**
- G3 makes any handshaking device an update source.
- A phone is often asleep or offline, and must not listen: cf-serverd dies with Termux, and loopback is limited on 17.
- The map does not say how the phone gets updates.

**Evidence:** G3 text; X-android-06 and X-android-12 sources.
**Proposed text:**

> Android pulls: on wake, charge or network change the agent fetches the newest signed goal bundle from any reachable peer, verifies the handshake offline, keeps the last approved bundle, and queues logs for the Mac. Peers push only when the device is reachable; no inbound port is required.

**Merge:** needs the operator's ruling first (the Android update design: pull on wake, no inbound port); then insert after that sentence
**Checked:** not checked (design inference; its premises, loopback and Termux, were checked under X-android-06 and X-android-12; confirming it needs a pull-on-wake prototype run on a real phone)

### X-android-14: G4 see-and-refuse on a phone

**Target:** `architecture-DEFINITIVE-v3.md` §6 adapter #2, after X-android-13's text
**Kind:** add
**Goal:** G4
**Weight:** blocks-goal
**Finding:**
- G4 requires the owner to see and refuse each diff, with a score and highlighted code, in CLI and TUI modes.
- On a phone, the TUI runs in Termux. Owners will mostly act from a notification.
- The map has no Android review surface.
- A retired proposal had one: `deprecated/architecture-proposal-openai-v1.md` §4, "Android consent gateway".

**Evidence:** G4 text; `docs/architecture/deprecated/architecture-proposal-openai-v1.md` §4.
**Proposed text:**

> On Android the diff is reviewed in Termux (`tendcf review`, CLI or TUI) or from the agent's notification, which opens the same diff, score, reason and highlighting with Accept and Refuse. With no answer the bundle is held; a refusal is logged.

**Merge:** needs the operator's ruling first (the Android review surface: Termux plus an agent notification); then insert after X-android-13's text
**Checked:** inferred (design); the deprecated section was read in an earlier pass, not re-read; independently checked 2026-11-13: confirmed

### X-android-15: qualify "comprehensive" in public claims

**Target:** `docs/review-2026-11-13/00-goal-definition.md` G5, at "comprehensive configuration management that works with Island/Insular profiles"
**Kind:** question
**Goal:** G5, G8.3
**Weight:** improves
**Finding:**
- At shell UID, some surfaces are out of reach: other apps' data, user restrictions, a work profile whose owner sets `DISALLOW_DEBUGGING_FEATURES`.
- AMAPI and Fleet are declarative too, but enterprise-owned.
- The defensible claim is the combination: convergent, owner-controlled, work-profile-aware, no MDM, no root.
- The goal is agreed, so this is for public docs, not the goal.

**Evidence:** §2 of this report.
**Proposed text:**

> (For the paper and the public docs, not the goal:) tendcf converges an owner's own unrooted Android phone, including its Island/Insular work profile, from the same signed goal file as the owner's other machines, without an MDM enrollment or root.

**Merge:** needs the operator's ruling first (wording of the public claim)
**Checked:** not checked (the independent check found no counter-example but cannot prove there is none; confirming it needs a wider survey of Android configuration tools; see "The differentiator claim, restated accurately")

## Ideas and risks

1. **Risk: the helper is the single point of failure.** Fork churn on Android 17 is heavy (#19), thedjchi has paused, and ShizukuTendCF inherits both. Mitigation: keep the app-tier and shell-tier promises separable, and keep a pinned-to-latest CI build of the fork.
2. **Risk: malware shares the architecture.** Malware already copies the Shizuku architecture (HackTricks). A trusted-signer allowlist (ShizukuTendCF) and G4's refusal are the defence. Say so in the security model.
3. **Idea: steal AppManagerNG's preview UX.** Its "profiles preview the selected packages before freezing" is the closest existing G4-like screen; it is GPL-3+.
4. **Idea: Island's Open API is the sanctioned work-profile route.** Test it before building any shell-into-user-10 path.
5. **Risk: Termux distribution.** F-Droid-signed Termux may not register under verification (gist). Plan for the GitHub build, or for registering the agent and installing Termux through shell.
6. **Risk: there is no device-owner path without a factory reset.** For G8.3 strangers, design for PO-plus-shell and treat DO as optional.
7. **Idea: per-app network block resets on reboot.** It is a natural first convergent promise: re-asserted every run, visibly drifting otherwise.
8. **Risk: Samsung Secure Folder and Private Space.** These are profiles that neither shell nor Island controls. Model them as `not_managed`, never silently skipped.
9. **Idea: limited distribution (up to 20 devices per Google's FAQ; the limited-distribution guide, updated 2026-10-28, says 50; confirm before relying on either) fits G8.1–G8.2.** It covers the owner's fleet without an identity filing. Decide before 2027.
10. **Risk: the map was written for "Android deferred".** Linux-shaped assumptions (cf-serverd listener, cf-execd, `processes:`) need an Android audit before step 2 starts.

## Withdrawn after checking

No item was withdrawn. Two claims the independent check refuted were corrected in place:

1. **Landscape table, Insular row.** Claim: licence "GPL-family". Evidence: F-Droid's page for `com.oasisfeng.island.fdroid` gives Apache-2.0, and the GitHub repo is a mirror of gitlab.com/secure-system/Insular (Apache-2.0). Now reads Apache-2.0.
2. **§2 "What fails" item 1 (the checker's "§3 constraint 1").** Claim: stayturgid saw a `pm install --user 10` time out on a confirmation dialog. Evidence: `android_apk.py:955-981` runs `adb install -r --user N` and only warns on a timeout; no observed failure is recorded. Now describes the timeout branch.

Not checked:
- Sui, Flyve, Obtainium, Canta, Tasker/Automate, GrapheneOS tools (no pages fetched)
- the AOSP Shell manifest permission list
- whether a Shizuku Binder reaches apps in user 10
- Fleet's Android GitOps specifics
- the Termux Play build
- licences marked "not re-checked"
- the local nix-on-droid evaluation (not read)
- no device was touched

Last search run: firecrawl search "CFEngine custom promise types module protocol docs" (2026-11-13) led to the docs.cfengine.com custom page (fetched); no later source contradicts §2.
