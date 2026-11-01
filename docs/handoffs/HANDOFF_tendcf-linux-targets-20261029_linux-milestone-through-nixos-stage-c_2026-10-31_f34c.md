---
schema_version: 1
handoff_id: f34c
parent_handoff_ids: []
lineage: none
chain: [tendcf-linux-targets-20261029]
repo: tendcf
workspace: main
branch: master
head_sha: 2933a71eaf92cbb40cc7a093213132eb3246f057
created_at: 2026-10-31T21:12:55-0400
writer: omp
---
# Handoff — Linux milestone through NixOS stage C

## The Goal

`docs/architecture/linux-targets.md` §3: make the generic bundle run on Linux
(systemd adapter, schema bump, one enforced service on pastebin), then start the
NixOS passthrough (step 8). This session took the milestone from "steps 1-3 merged"
to "steps 4-5, 7 and 8 stages A-C merged and deployed", plus the fork refresh and
two CI blind spots found live.

## Where We Are

Everything is merged and deployed; nothing is dirty, dispatched or half-done.

1. tendcf `master` `2933a71`: PRs #11-#23 this session (step 5 systemd adapter;
   step 4 slice A `schema_version` 2 and slice B writers `schema_version` 3; step 7
   installer, canary, runbook, bare-host test, read-only-store guard; NixOS plan and
   its stage records; docs refresh). `overlay/fork.json` pins `tendcf-integration`
   `b8abf2840` (fork master `b0f6da2dd` merged; PR #14).
2. `site-public-djbclark` `master` `035fd13`+: `nixos/pkgs/cfengine-tendcf.nix`,
   `nixos/modules/cfengine-tendcf.nix` (off by default), workflow
   `nixos-cfengine-build.yml` incl. the stage B closure diff (PRs #241, #242).
   vps-primary imports the module and does not enable it.
3. pastebin (T3): root-owned `/opt/tendcf` at tendcf `4855f56`, canary
   `tendcf.canary.service` enforced, root `cf-execd` (`tendcf-execd.service`)
   restores drift in under 5 min. No sudoers rule; operator granted root SSH.
4. get.sipb.cloud (T5): image `forgejo.mit.edu/djbclark/get` at `bf3bc63` carries the
   module (`enable = true`, `execd.enable = false`); `/var/lib/cfengine-tendcf` holds
   the passthrough CMDB data; `cf-agent -n` actuates nothing; a systemd entry is
   refused with the `nixos` unit-writer message. Nothing scheduled there.
5. Tier 1 pointer `~/.local/state/handoffs/tendcf/main/SESSION_LOG.md` is current.

## What We Tried

1. **`/etc/systemd/system` guard by `isdir` alone.** First guard was "Linux booted by
   systemd"; the vps-primary probe showed `/etc/systemd/system` is a read-only store
   symlink there, so the adapter would half-fail. Replaced by
   `tendcf_systemd_units_writable` (real, non-symlink dir) in PR #20.
2. **Installer assumed `/var/cfengine`, then `$prefix/var/cfengine`.** Both wrong: the
   fork build's compiled-in work directory is `/opt/tendcf/var/libntech` (libntech's
   own configure names it). The installer now reads `sys.workdir` from `cf-promises
   --show-vars`; two CI rounds lost to the guesses.
3. **Trusting RUNPATH for bundled librsync/libb2.** `cf-*` binaries carry a RUNPATH
   but `libpromises.so`'s own dependencies are not resolved through it, so pastebin
   (no system librsync) could not start `cf-promises`; CI never saw it because apt
   installs librsync. Fixed by pinning `LD_LIBRARY_PATH=/opt/tendcf/lib` in the
   installer and the unit (PR #15) and a bare-host regression test (PR #16).
4. **Stage C as `nixos-rebuild test`.** get is an image, not a rebuilt host; the plan's
   wording did not fit. Done instead by adding the module to get's flake and moving
   `:latest` (one reboot).
5. **`fetchSubmodules` for the fork.** Not possible: the fork's libntech commit exists
   only on djbclark/libntech; the Nix package fetches libntech separately and copies it
   in (slice report in `~/.local/state/bigteam/nixos-cfengine-tendcf-20261031/`).
6. **`get.xvm.mit.edu`**: does not resolve; the host is `get.sipb.cloud`, SSH on exposed
   port 14719 (Hyades `getconf get`).

## Key Decisions

The pastebin enforce path is CFEngine's own shape (root-owned install, root
`cf-execd`, no sudoers rule), chosen after reading the book (ch. 19, 21, 23 via the
Basic Memory index) and the cf-execd/MPF docs; a NOPASSWD rule on a user-writable
tree was rejected as an escalation path. Step 4 was split: slice A (systemd
`restart`/`wanted_by` and a safe argv alphabet, refuse-not-escape) and slice B writers
(`nixos`, `dpkg`) landed; inventory fields stay deferred until step 6 reads them.
Stage A was written by an omp Sonnet 5.5 bigteam slice (router's pick under a tight
Claude guard); the orchestrator fixed two build facts the slice could not know
without a build. The first NixOS host is get, not vps-primary, because it is
disposable.

## Decisions

- [decision] systemd adapter guards on a real writable /etc/systemd/system, not only "booted by systemd"; rejected: refuse by goal-file convention only; because NixOS has a read-only store symlink there and a write would half-fail; in [PR 20](https://github.com/frdminc/tendcf/pull/20).
- [decision] pastebin runs a root-owned /opt/tendcf with a root cf-execd and no sudoers rule; rejected: NOPASSWD rule on ~/cf; because a passwordless root cf-agent over a user-writable tree is an escalation path and CFEngine's documented model is a root daemon; in [PR 13](https://github.com/frdminc/tendcf/pull/13).
- [decision] installer reads the work directory from cf-promises; rejected: hard-coding /var/cfengine; because the fork build compiles in /opt/tendcf/var/libntech; in [PR 13](https://github.com/frdminc/tendcf/pull/13).
- [decision] systemd argv and working_dir are held to a safe alphabet and refused, not escaped; rejected: escaping into ExecStart; because systemd re-reads quotes, backslash, $ and %, and refusal is one spelling; in [PR 12](https://github.com/frdminc/tendcf/pull/12).
- [decision] step 4 split into slice A (systemd fields, schema_version 2) and slice B writers (schema_version 3); rejected: one bump with inventory fields; because nothing renders the inventory fields yet; in [PR 18](https://github.com/frdminc/tendcf/pull/18).
- [decision] the cfengine-tendcf derivation and module live in site-public-djbclark/nixos; rejected: a separate flake repo; because linux-targets.md section 2 already says the host flake; in [site-djbclark PR 241](https://github.com/djbclark/site-djbclark/pull/241).
- [decision] stage C ran on get.sipb.cloud by adding the module to its image; rejected: nixos-rebuild test on vps-primary; because get is disposable and backed up; in [PR 21](https://github.com/frdminc/tendcf/pull/21).
- [ruling] "Go ahead and use your ssh root@pastebin.xvm.mit.edu access to set up sudoers in whatever way you need to" (djbclark, 2026-10-31); no sudoers rule was needed once root SSH was available.
- [ruling] "make sure in AGENTS.md or whatever that it prompts you to make heavy use of our Basic Memory index of the cfengine book as that is a low token high value source of correct information" (djbclark, 2026-10-31)
- [ruling] "Leave it running as the standing proof" (djbclark, 2026-10-31; the pastebin canary)
- [ruling] "Defer until step 6/8 needs it" (djbclark, 2026-10-31; step 4 slice B inventory fields)

## Relations

- decided_in [[HANDOFF_tendcf-linux-targets-20261029_linux-milestone-through-nixos-stage-c_2026-10-31_f34c]]

## Evidence & Data

1. Pastebin: `cf-execd` restored a stopped canary at 17:35:02 local after a stop at
   17:31:57; `systemctl show -p Restart` = `on-failure`, `User=nobody`; second
   `run-once` printed no `systemctl` line. `/etc/sudoers.d` = `README`, `pbbackup`.
2. Stage B closure diff (CI, site-djbclark #242): new paths `cfengine-tendcf-3.29.0a.b8abf2840`
   (4.3 MiB), `librsync-2.3.4-lib`, `libyaml-0.2.5`, `lmdb-0.9.35`; nothing else.
3. get after deploy: `nixos-version --configuration-revision` = `bf3bc634…`;
   `/etc/systemd/system -> /etc/static/systemd/system`; `cf-agent --version` =
   `CFEngine Core 3.29.0a.b8abf2840`; `cf-agent -n` warning only:
   `sys.os_name_human` "Unknown" (`sys.flavour` = `nixos_26`).
4. Fork issues filed: [djbclark/core#55](https://github.com/djbclark/core/issues/55)
   (USERMOD outside `HAVE_USERMOD` guard, `cf-agent/verify_users_pam.c:1651`),
   [djbclark/core#56](https://github.com/djbclark/core/issues/56) (NixOS not in
   `libenv/sysinfo.c` `SetOsNameHuman`). Dupe-searched djbclark/core and cfengine/core;
   nearest thread #50 (Termux, closed).
5. Stage A slice: `acp-run omp claude-sonnet-5-5` 305 s, 28 tools, $0.88; report at
   `~/.local/state/bigteam/nixos-cfengine-tendcf-20261031/stage-a-report.md`.
6. Tests: `tests/policy/run.sh` passes on Mac (checks 1-4, 6 refusal path) and on CI
   (VMs: check 6 lifecycle; debian-13: check 7 NixOS shape); `tests/deploy/*.sh` green
   on CI; `bin/schema_lint.py` 63 negative fixtures; `deploy/linux/canary/check.py` 3
   goal files.

## Operator Feedback

1. Prior art first for privilege design, and cite the book through Basic Memory
   (now in `AGENTS.md`).
2. Choose model strength per slice and run it through a `/bigteam` runner; the lead
   session was switched to Fable for the schema design work.
3. Absolute paths in worktrees (three stray edits caught; rule now in `AGENTS.md`).
4. Options numbered in every chooser; links in prose, not cards.

## Where We're Going

1. **Stage D ruling** (`docs/architecture/nixos-passthrough-plan.md` §3): decide what,
   if anything, tendcf enforces on a Nix host (files, report channel; never services)
   before any `cf-execd` is enabled there. Ask djbclark with the plan's §4 candidates
   (evaluated-config JSON vs flake lock + Nix-side diff) rendered from get's real
   `systemctl list-unit-files`.
2. Open design item: the unit-writer prefix pattern (`^[a-z][a-z0-9]*(\.[A-Za-z0-9][A-Za-z0-9_-]*)+\.\*$`)
   does not fit NixOS unit names (`afsd.service`); `deploy/linux/passthrough/goal-file.json`
   uses `org.nixos.*` as a placeholder. Settle with a host-level `supervisor: nixos`
   inventory fact (deferred slice B field) or a whole-namespace prefix; schema bump.
3. vps-primary: module imported, not enabled; enabling it is its own go-ahead
   (`services.cfengine-tendcf.enable` in `nixos/vps-primary/configuration.nix`,
   deploy from the pushed head, AGENTS rule 36).
4. Step 6 nix2cf systemd renderer (`~/src/nix2cf`) needs the deferred inventory
   fields (`supervisor`, distro family): one `schema_version` bump when it lands.
5. Upstream #55/#56 to cfengine/core through the cfengine-all session's process
   (it ranked the fork issues today; relay id 2291cae0).
6. Pastebin canary stays running (ruling); removal is
   `tendcf-install.sh data deploy/linux/canary/host_specific-absent.json` + `run-once`.

## Detached jobs

none (the one slice record, `~/.local/state/bigteam/nixos-cfengine-tendcf-20261031/jobs/stage-a.json`, is closed).

## Quick Start

```bash
cd ~/src/tendcf && git pull --ff-only && git log --oneline -3
~/.claude/hooks/handoff-tools/.venv/bin/python ~/.claude/hooks/handoff-tools/session_log.py read \
  --state-root ~/.local/state/handoffs --dir ~/.local/state/handoffs/tendcf/main
sed -n 1,80p docs/architecture/nixos-passthrough-plan.md          # stages, decisions, open items
ssh -p 14719 djbclark@get.sipb.cloud 'nixos-version --configuration-revision; systemctl list-unit-files --type=service | head'
ssh root@pastebin.xvm.mit.edu 'systemctl is-active tendcf-execd.service tendcf.canary.service; cat /opt/tendcf/share/tendcf/REVISION'
bm tool search --project books "<CFEngine question>"               # the book, first move
```
