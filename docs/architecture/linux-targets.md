# Linux targets (decided 2026-10-29)

> Operator ruling, 2026-10-29. Status: current. Android/Termux is deferred;
> Linux is the platform for build-order Steps 1 and 3 until further notice.

## 1. Targets

| # | Target | OS | Arch | Role |
| --- | --- | --- | --- | --- |
| T1 | GitHub CI | `ubuntu-24.04`, `ubuntu-26.04` | x86_64; arm64 as smoke row (`-arm` labels) | builds and tests; full VMs with systemd as PID 1, so the adapter runs in enforce mode there |
| T2 | CI, Debian | `debian:13` container job | x86_64 | builds the Debian package, matches T3 |
| T3 | pastebin.xvm.mit.edu | Debian 13 (trixie), kernel 6.12, systemd | x86_64 | first live Linux host: dry-run, then one stateless service enforced |
| T4 | vps-primary | NixOS 26.05, kernel 6.18, systemd | x86_64 | **not in the first milestone** (operator); later observe-only |
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
| 2 | In parallel: CI builds the fork's `cf-agent` on T1/T2 and runs the generic-bundle tests on Linux; read-only probe of T3 (os-release, glibc, systemd version, unit paths and owners). |
| 3 | Fail-closed guard in `policy/tendcf_services.cf`: refuse any unit flavour the bundle does not implement, with a negative test. Today it is launchd-only and would render a systemd entry as a `LaunchDaemons` plist. |
| 4 | One `schema_version` bump from an adapter prototype: richer goal-file systemd flavour (scope, restart, install target, externally-written unit), writer vocabulary with `dpkg` and `nixos`, and an inventory schema carrying `supervisor` and distro family. |
| 5 | systemd branch of the generic bundle, enforce tests on T1. |
| 6 | nix2cf: systemd renderer (supervisor from inventory), the Linux-relevant `TODO(operator)` markers, the `tendcf.lock` consumer. nix2cf emits only the goal file; Augments stay on the device (`projector.py`). |
| 7 | T3 dry-run, then one enforced service. |
| 8 | T4 observe-only; decide whether nix2cf emits NixOS modules. Then T5/T6/T7. |

## 4. Consequences of deferring Android

1. The `termux` Site Model block, the `runit` goal-file flavour and the
   `android-termux-services` fixture stay. Deleting any is a schema bump
   for nothing. `runit` also covers Linux distributions that use it.
2. Android may still change the adapter shape later; that costs a
   `schema_version` bump and a baseline ceremony per device. Accepted.
3. D18 (agent-owned JSONL report rows) needs a Linux writer. Open.
4. Secrets on a headless host: a secretspec provider must be chosen
   before any `Environment=` is rendered.
