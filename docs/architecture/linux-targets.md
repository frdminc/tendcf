# Linux targets (decided 2026-10-29)

> Operator ruling, 2026-10-29. Status: current. Android/Termux is deferred;
> Linux is the platform for build-order Steps 1 and 3 until further notice.

## 1. Targets

| # | Target | OS | Arch | Role |
| --- | --- | --- | --- | --- |
| T1 | GitHub CI | `ubuntu-24.04`, `ubuntu-26.04` | x86_64; arm64 as smoke row (`-arm` labels) | builds and tests; full VMs with systemd as PID 1, so the adapter runs in enforce mode there |
| T2 | CI, Debian | `debian:13` container job | x86_64 | builds the Debian package, matches T3 |
| T3 | pastebin.xvm.mit.edu | Debian 13 (trixie), kernel 6.12, systemd | x86_64 | first live Linux host: dry-run, then one stateless service enforced |
| T4 | vps-primary | NixOS 26.05, kernel 6.18, systemd | x86_64 | **not in the first milestone** (operator); the first passthrough host (§5) |
| T5 | get.sipb.cloud | NixOS today (Hyades libkrun microVM) | x86_64 only | revived later as a stripped-down podman image |
| T6 | podman images | NixOS, Debian 13, Ubuntu 24.04 | x86_64 | on Hyades, as needed |
| T7 | Apple `container` | NixOS, aarch64 | aarch64 | optional local iteration only; prefer CI over Mac resources |

OS and kernel versions for T3 and T4 were read from the hosts on 2026-10-29.
`cf-agent` is not installed on either.

## 2. Build

Every target runs the **full fork build** of CFEngine (security fixes and
`--simulate-json`), built in GitHub CI. CFEngine's supported-platform list
(3.27: Debian 12 and 13, Ubuntu up to 24.04) does not bind us. See the
ruling in [`upstream-overlay.md`](upstream-overlay.md) §2. The NixOS build
is a derivation kept in the host flake, not in this repo.

## 3. Order

| # | Step |
| --- | --- |
| 1 | Record these decisions. |
| 2 | In parallel: CI builds the fork's `cf-agent` on T1/T2 and runs the generic-bundle tests on Linux; read-only probe of T3 (os-release, glibc, systemd version, unit paths and owners). **Started 2026-10-29:** `.github/workflows/linux.yml` builds the commit pinned in `overlay/fork.json` on ubuntu-24.04, ubuntu-26.04, ubuntu-24.04-arm and a `debian:13` container (install tree uploaded for T3), then runs `tests/policy/run.sh` (cf-promises wiring against `examples/host_specific.json`; enforce-mode interlock refusal with no actuation, and the satisfied twin that exposed the 2026-10-29 verdict-ordering defect, fixed in the same change). The pin follows the refreshed `tendcf-integration` (fork `master` + every current fix branch + the `simulate-json` series), see [`upstream-overlay.md`](upstream-overlay.md) §2. T3 probe done (§1). |
| 3 | Fail-closed guard in `policy/tendcf_services.cf`: refuse any unit flavour the bundle does not implement, with a negative test. **Done 2026-10-29:** a present entry is actuated only when its `unit` flavour is `launchd` AND the host is `darwin`; otherwise it is refused and reported by name and flavour. `tests/policy/run.sh` checks 4 (systemd entry, every host) and 5 (launchd entries on a non-Darwin host, CI only). Before this, a systemd entry would have been rendered as a `LaunchDaemons` plist and a launchd entry on Linux handed to a `launchctl` that is not there. |
| 4 | One `schema_version` bump from an adapter prototype: richer goal-file systemd flavour (scope, restart, install target, externally-written unit), writer vocabulary with `dpkg`, `nixos` and `nix-darwin`, and an inventory schema carrying `supervisor` and distro family. **Slice A done 2026-10-31:** the family went to `schema_version: 2` (goal-file, goal-diff and approval-record; every fixture and digest regenerated; case 13 now claims 3). `unit.systemd` gained `restart` (`no`/`on-failure`/`always`) and `wanted_by` (a `*.target`), the two knobs the renderer writes, both explicit. A systemd entry's argv and `working_dir` are held to a safe alphabet (no `"` `\` `$` `%` or control character; `working_dir` limited to `[A-Za-z0-9._+@:-]` segments): refused structurally, not escaped, so a value systemd would re-read never reaches the unit file (`service_present` `allOf`; negative cases 70-72). Left for slice B, because nothing renders them yet: `scope`, externally-written unit, the writer vocabulary and the inventory fields. |
| 5 | systemd branch of the generic bundle, enforce tests on T1. **Done 2026-10-31 (PR #11):** a present `systemd` entry on a host booted by systemd (`/run/systemd/system`) renders `/etc/systemd/system/<id>` from `policy/templates/systemd.service.mustache`, then `daemon-reload`, `enable`/`disable` per `enabled`, `start` (or `restart` when a running unit changed); a tombstone with a unit file present runs `disable --now`, deletes the file, reloads. State probes are run-cached snapshots, so one run converges and the next issues no `systemctl`. `tests/policy/run.sh` check 6 runs that lifecycle against the real manager on the three ubuntu VM jobs (`TENDCF_TEST_SYSTEMD=1`, passwordless sudo; unit passes `systemd-analyze verify`) and the refusal path on `debian:13` and Darwin; check 4 now uses a runit entry. The prototype's gaps (no restart policy, unescaped argv) closed in step 4 slice A. |
| 6 | nix2cf: systemd renderer (supervisor from inventory), the Linux-relevant `TODO(operator)` markers, the `tendcf.lock` consumer. nix2cf emits only the goal file; Augments stay on the device (`projector.py`). |
| 7 | T3 dry-run, then one enforced service. **Dry-run done 2026-10-29:** the `debian:13` CI artifact (`cfengine-fork-debian13`, fork `7363abf43`) installed under `~/cf` on pastebin as the unprivileged user; `tests/policy/run.sh` passes all five checks there, and `cf-agent -n` on `examples/host_specific.json` refuses both entries by name (interlock unmet: the example's caddy path is a Mac path; service: `launchd` flavour on `debian_13`) and touches nothing. Found on the way: the artifact needed `librsync`/`libb2` bundled (now done) and the harness had to own its umask (pastebin is 002). **Enforced service, plan decided 2026-10-31:** the canonical CFEngine shape, not a sudoers rule. pastebin's sudo asks for a password and `~/cf` is user-writable, so a passwordless root `cf-agent` there would be an escalation path; CFEngine's own model is a root-owned install and a root `cf-execd` (book ch. 19, 21, 23; [cf-execd](https://docs.cfengine.com/docs/lts/reference/components/cf-execd), [MPF](https://docs.cfengine.com/docs/lts/reference/masterfiles-policy-framework); an unprivileged `cf-agent` cannot do root work, [CFEngine blog](https://cfengine.com/blog/2024/feature-friday-25-unprivileged-execution)), and our v3 design already self-bootstraps each host. Stage A, one password-sudo session: install `/opt/tendcf` root-owned, place the policy and the canary data, one `cf-agent -K -I` run, inspect. Stage B: enable a root `cf-execd`. The canary is `tendcf.canary.service` (`sleep infinity` as `nobody`), its CMDB data a projection of a schema-valid goal file. No masterfiles framework: the installer copies the policy in as root. The CI build now uses `--prefix=/opt/tendcf` so the binaries' library path is root-owned; `tests/deploy/linux-install.sh` runs the full sequence on the ubuntu VMs. Runbook and files: [`deploy/linux/`](../../deploy/linux/README.md). **Done on pastebin 2026-10-31 (tendcf `8f63225`, fork `b8abf2840`):** operator granted root SSH, so the installer ran as root with no sudoers rule left behind. Stage A: canary rendered, enabled, active as `nobody` with `Restart=on-failure`; a second run issued no `systemctl` command. Stage B: a root `cf-execd` (`tendcf-execd.service`) restored the canary within 3 minutes of a manual stop. Found live, invisible to CI (apt installs librsync there): `RUNPATH` on the `cf-*` binaries is not inherited by `libpromises.so`'s own dependencies, so the bundled `librsync`/`libb2` were not found; the installer and the unit now set `LD_LIBRARY_PATH=/opt/tendcf/lib`. The canary is left running under `cf-execd`; its tombstone is the removal path. |
| 8 | T4: the NixOS passthrough adapter (§5), dry-run first. Then T5/T6/T7. |

## 4. Consequences of deferring Android

1. The `termux` Site Model block, the `runit` goal-file flavour and the
   `android-termux-services` fixture stay. Deleting any is a schema bump
   for nothing. `runit` also covers Linux distributions that use it.
2. Android may still change the adapter shape later; that costs a
   `schema_version` bump and a baseline ceremony per device. Accepted.
3. D18 (agent-owned JSONL report rows) needs a Linux writer. Open.
4. Secrets on a headless host: a secretspec provider must be chosen
   before any `Environment=` is rendered.

## 5. Nix (ruling 2026-10-29)

> Operator goal, 2026-10-29: a person brings their existing NixOS or
> nix-darwin configuration to tendcf **verbatim**, and a person who knows
> the Nix language writes tendcf configuration in it for hosts that are not
> Nix at all (macOS, Debian).

D12 is amended from "Nix modules MAY author the Site Model" to two paths,
both first-class:

1. **Passthrough.** On a host that already runs NixOS or nix-darwin,
   tendcf hands the host's Nix configuration to Nix unchanged. Services,
   packages and files stay Nix's; the unit writer for them is `nixos` or
   `nix-darwin`, not CFEngine. tendcf adds only the thin layer Nix does not
   do: distribution (lockfile, signed release, consent diff, pull),
   reporting, and whatever the configuration leaves out. No rewrite of a
   working configuration is ever required.
2. **Nix as an authoring language.** The Site Model's types are also Nix
   module options (`mkOption`, `mkIf`, `mkDefault`). A site authored in Nix
   evaluates (`nix eval --json --store dummy://`) to the same
   schema-validated goal file as one authored in YAML, and nix2cf renders it
   for a launchd or systemd host with no Nix installed. The person's Nix
   knowledge carries over; Nix the runtime is not needed on the target (D6
   unchanged).

YAML and Nix are equal frontends: each fixture authored in Nix has a YAML
twin, and the two must render to byte-identical goal files. Nobody has to
learn Nix; nobody has to abandon it.

Consequences:

1. T4 is a named milestone (Step 8), still after the Debian milestone.
2. nix-darwin on the primary workstation (`architecture-DEFINITIVE-v3.md`
   §14.1) is only about that one host. The nix-darwin passthrough adapter
   is required either way and shares the Step 8 design.
3. The Step 4 schema bump adds `nix-darwin` to the writer vocabulary next
   to `nixos`.
4. Open, decided at Step 8: how a passthrough host's goal file carries the
   Nix side so that the consent diff (`architecture-DEFINITIVE-v3.md` §9)
   still renders in ordinary language. Candidates: the evaluated
   configuration's JSON, or the flake lock plus a Nix-side diff. The Nix
   frontend (path 2) is not built; until it is, the files are YAML.
