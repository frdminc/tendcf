# NixOS passthrough: probe findings and dry-run plan (step 8 prep)

Status: proposed 2026-10-31, awaiting operator sign-off. Nothing on vps-primary
has been changed; every command below that touches the host is read-only or
runs as an unprivileged, store-only build.

## 1. What the read-only probe found (vps-primary, 2026-10-31)

| Fact | Evidence | Consequence |
| --- | --- | --- |
| NixOS 26.05 (`ID=nixos`), systemd 260, Nix 2.34 with `flakes nix-command` | `nixos-version`, `systemctl --version`, `nix show-config` | the flake route works as is |
| No CFEngine anywhere in the running system closure | `nix-store -qR /run/current-system` has no `cfengine` path | nothing to conflict with; the first install is ours |
| `/etc/systemd/system` is a symlink into `/etc/static` and the store; a write fails with `Read-only file system`; `/nix/store` is mounted read-only | `touch /etc/systemd/system/.probe` | **the generic systemd adapter cannot work here**, by design: on NixOS a unit exists only if the system configuration declares it |
| `/opt` does not exist; `/var/lib` is writable | `ls` | CFEngine's work directory can live under `/var/lib`; the binaries come from the store, not `/opt/tendcf` |
| 21 running services; root's SSH keys are declared in the configuration | `systemctl`, `configuration.nix` | tendcf must not touch any of them (writer is `nixos`) |
| The host configuration lives in `site-public-djbclark/nixos/` (flake, `vps-primary/configuration.nix`); deployed from the pushed branch head by `deploy-vps-primary` | repo layout, AGENTS.md rule 36 | the CFEngine derivation and module belong in that flake (linux-targets.md §2), not in this repo |

## 2. Design consequence: tendcf must refuse, not attempt

Today the generic bundle treats any Linux host booted by systemd as a systemd
adapter host (`policy/tendcf_services.cf`, `tendcf_systemd_host`). On vps-primary
that is true and the entry would be actuated: the render would hit a read-only
filesystem and `systemctl enable` would error, noisily and half-done. The
passthrough design (linux-targets.md §5) says services on a Nix host stay Nix's,
so the bundle must refuse a CFEngine-written unit there as a matter of policy,
not as a side effect of a failed write.

Rule to implement first (**done 2026-10-31**, `tendcf_systemd_units_writable` in
`policy/tendcf_services.cf`; `tests/policy/run.sh` check 7 reshapes the debian-13
container into this layout and proves the refusal): the systemd adapter is supported only where
`/etc/systemd/system` is a real writable directory (not a symlink into a store),
and a present `systemd` entry elsewhere is refused by name, with a message that
says the host's unit writer is `nixos`. Negative test: the same fixture on a
host where `/etc/systemd/system` is a read-only symlink (a CI container can
bind-mount one) must run no `systemctl` and write nothing.

## 3. The dry run, in four stages

Each stage ends with output you can read, and none installs anything on the
host until stage C.

1. **A. Build the fork as a Nix derivation, off the host.** **Done 2026-10-31**
   ([site-djbclark PR #241](https://github.com/djbclark/site-djbclark/pull/241)):
   `nixos/pkgs/cfengine-tendcf.nix` (fork `b8abf2840`, libntech `d379dce` from the
   fork, `autoreconfHook`, `--with-workdir=/var/lib/cfengine-tendcf`, compiled-in
   version `3.29.0a.b8abf2840` via a written `CFVERSION`), module
   `services.cfengine-tendcf` (`enable` and `execd.enable`, both default off) imported
   into vps-primary without enabling it, and the workflow `nixos-cfengine-build.yml`
   (GitHub `ubuntu-latest` with Nix, not the VPS) that builds the package, asserts the
   version, rebuilds the host toplevel and checks the gating. Two build findings:
   `libpromises/text2cstring.pl` has a `/usr/bin/perl` shebang (patched), and
   `cf-agent/verify_users_pam.c` uses `USERMOD` outside its `HAVE_USERMOD` guard
   (upstream defect, filed as [djbclark/core#55](https://github.com/djbclark/core/issues/55); `shadow` on the build PATH bakes store paths in). Written by omp
   Sonnet 5.5 as a bigteam slice; the two fixes by the orchestrator. Original text: In the host flake,
   a `cfengine-tendcf` package pinned to `overlay/fork.json`'s commit (the same
   `core` commit CI tests; libntech from core's submodule pointer). Build it on
   Forgejo CI or a Linux builder, never on vps-primary (AGENTS.md rule 36: heavy
   builds off the VPS). Output: a store path and a build log.
2. **B. Evaluate the module without activating it.** **Done 2026-10-31**
   ([site-djbclark PR #242](https://github.com/djbclark/site-djbclark/pull/242)): CI builds an
   `extendModules` twin of vps-primary with the module enabled and diffs closures; the
   only new store paths are `cfengine-tendcf` (4.3 MiB), `librsync`, `libyaml`, `lmdb`.
   Original text:
   `nix build .#nixosConfigurations.vps-primary.config.system.build.toplevel`
   with the new module enabled, on the builder, then `nix store diff-closures`
   against the running system. Expected diff: the CFEngine package, one
   systemd unit for `cf-execd`, a tmpfiles entry for the work directory. Anything
   else is a finding. Read-only for the host.
3. **C. First activation, dry-run only.** **Done 2026-10-31 on get.sipb.cloud**
   (not `nixos-rebuild test`: get is an image, so the module went into its flake,
   [forgejo djbclark/get `bf3bc63`](https://forgejo.mit.edu/djbclark/get), `:latest` deployed,
   one reboot; `execd.enable = false`). On the rebooted host: `/etc/systemd/system` is the
   read-only store symlink, `/var/lib/cfengine-tendcf` exists from tmpfiles, `cf-agent` is
   `3.29.0a.b8abf2840`. With `deploy/linux/passthrough/host_specific.json` as CMDB data,
   `cf-promises` accepts the policy and `cf-agent -n -K -I` actuates nothing; with the
   `systemd-present` fixture it refuses the entry by name with the `nixos` unit-writer
   message (PR #20's guard), writes nothing, runs no `systemctl`. One finding: CFEngine's OS
   detection does not know NixOS (`sys.os_name_human` "Unknown" warning; `sys.flavour` is
   `nixos_26`, so classes work): filed as [djbclark/core#56](https://github.com/djbclark/core/issues/56). get keeps the package and the work
   directory; nothing is scheduled there. Original text: `nixos-rebuild test` (activates
   without making it the boot default, so a reboot returns to the old system)
   with `cf-execd` **not** enabled; the module installs the binaries and work
   directory only. Then, as root over SSH, one `cf-agent -n -K -f ...` against
   the passthrough goal file (below). `-n` makes no change. Output: the refusal
   lines and the report rows.
4. **D. Stop and read.** No `switch`, no enforcement. Enforcement on this host
   is a separate, later ruling, because the only things tendcf could enforce
   here are files and the report channel, never services.

## 4. The passthrough goal file for this host

Open question from linux-targets.md §5, to be settled by stage C's output rather
than argued in advance: how the Nix side appears in the goal file so the consent
diff stays in ordinary language. The two candidates are the evaluated
configuration's JSON and the flake lock plus a Nix-side diff. Stage B already
produces both (`nix eval --json` of the options tendcf cares about; the
`diff-closures` text), so stage C can render each next to the real host and the
choice can be made on an actual diff. The goal file for stage C declares the
`unit-writer` for the host's unit namespace as `nixos` and carries no
`service` entries, so `cf-agent -n` has nothing to actuate and should report
nothing but its own health. First cut: `deploy/linux/passthrough/goal-file.json`
(`schema_version: 3`, writer `nixos` on `org.nixos.*`), projecting to
`{"vars":{}}`. Open, for stage C: the unit-writer prefix pattern is reverse-DNS
with two labels or more, and NixOS unit names are not (`afsd.service`,
`sshd.service`); a passthrough host needs either a whole-namespace prefix or a
host-level `supervisor: nixos` fact (the deferred inventory field), decided
against the real `systemctl list-unit-files` output.

## 5. Work this unlocks, in order

1. Bundle guard from §2 plus negative test (this repo, small PR, CI on the VM
   and Debian jobs).
2. Step 4 slice B's `nixos` and `nix-darwin` writer vocabulary and the inventory
   `supervisor`/distro family, needed by the goal file in §4 (schema bump).
3. Stages A to D in the host flake.

## 6. Decisions for the operator (taken 2026-10-31)

1. The derivation and module live in `site-public-djbclark/nixos/`: **yes**.
2. Stage C runs first on **get.sipb.cloud** (T5: NixOS 26.11, systemd PID 1,
   `/etc/systemd/system` a read-only store symlink like vps-primary, Nix 2.34
   with flakes, 4 CPU / 8 GB, `/persist` volume; SSH as `djbclark` on exposed
   port 14719, `wheel`; no real function, fully backed up, so disposable),
   then vps-primary. `get.xvm.mit.edu` does not exist; the host is
   `get.sipb.cloud`.
3. The writer vocabulary landed as `schema_version: 3` (this PR); inventory
   fields stay deferred.

Original questions:

1. May the CFEngine derivation and module land in `site-public-djbclark/nixos/`
   (the host flake), as linux-targets.md §2 already says?
2. Is `nixos-rebuild test` on vps-primary acceptable for stage C (reversible by
   reboot), or should stage C run on a throwaway NixOS VM first (T5/T6 images)?
3. Slice B's schema bump is now needed by stage C's goal file: do it before stage
   C, or hand-write the stage C goal file at `schema_version: 2` with the writer
   field unchecked (not recommended: it bypasses the lint this repo is built on)?
