# State 1 macOS VM: image prep and check harness

Slice A of [issue 70](https://github.com/frdminc/tendcf/issues/70): the scripts that
build and check state 1's Apple Silicon macOS VM on bigmac (tart 2.42.0). It follows
the 2026-11-17 answers on the issue: the pinned vanilla image as is, SSH only, key login,
Gatekeeper on, Recovery and the 50 GB disk kept, python.org Python 3.14.10 system-wide,
no CI for this image, no guest agent, no runner. **No VM has been run with these scripts
yet**; the tests use a fake `tart` and `ssh`.

| File | Role |
| --- | --- |
| `state1_vm.py` | the host-side driver: `resolve`, `pull`, `golden`, `check` (argv lists only) |
| `vmssh.py` | the SSH wrapper: argv in, remote exit status out (also a CLI) |
| `image.json` | the pin: repository, tag `27.2`, digest, Python version, URL and sha256 |
| `guest/prep.sh` | in-guest prep, run once as root by `golden` |
| `guest/install-python.sh` | in-guest python.org package install, run once as root by `golden` |
| `guest/bootstrap-askpass.sh` | `SSH_ASKPASS` helper for the single password login |
| `../../../tests/darwin/test_state1_vm.py` | the tests, no VM needed |

Placed under `deploy/darwin/` beside `deploy/linux/` (per-OS install and image
material) and the tests under `tests/darwin/` beside `tests/deploy/`; the existing test
runner is stdlib `unittest` discovery, so there is nothing new to install.

## Commands

Each is its own job and each is safe to re-run after an interruption. Run them from this
directory (or by path); the lead runs real passes through `bgrun`.

```sh
python3 state1_vm.py resolve                         # registry digest of the tag; no tart, no pull
python3 state1_vm.py pull                            # ~30 GB: its own job, so load-watch admits it alone
python3 state1_vm.py golden --pubkey ~/.ssh/KEY.pub  # build local VM state1-golden (add --rebuild to redo)
python3 state1_vm.py check  --identity ~/.ssh/KEY    # clone, check, reboot, delete; JSON on stdout
```

Common options: `--summary FILE` (write the JSON there, not to stdout), `--state-dir DIR`
(default `~/.local/state/tendcf-state1-vm`: lock, logs, pinned `known_hosts`, `golden.json`),
`--image FILE`. Exit status: 0 ok, 1 a step failed, 2 refused or bad usage, 130 interrupted.
`--identity` is the private key; a `.pub` path works when ssh-agent holds the key.
Use a key with no passphrase or one loaded in the agent, because ssh runs with `BatchMode=yes`.

- **`resolve`** reads the manifest digest for the pinned tag from the registry (an anonymous
  token and one HEAD request). It reports whether the tag has moved; the digest in
  `image.json` decides, not the tag.
- **`pull`** runs `tart pull <repo>@<digest>`. A no-op when that digest is already in the OCI
  cache. Tart's pull resumes, so re-run it after an interruption.
- **`golden`** refuses (exit 2) when the pinned image is not already in the OCI cache; it
  never pulls. It builds into `state1-golden-build` and renames to `state1-golden` last, so a
  half-built image is never the golden one. With `state1-golden` present it does nothing
  unless `--rebuild`. A leftover `state1-golden-build` is stopped and deleted first.
- **`check`** clones `state1-golden` to `state1-check-<run id>` and always deletes it, also on
  failure or on SIGINT/SIGTERM/SIGHUP. A clone left by a killed run is swept at the next start.

## Guards

- **Two-VM cap.** Before every `tart run` (including the restart after a reboot) the driver
  reads `tart list --source local --format json` and refuses when two VMs are running (Apple's
  licence allows two macOS VMs per host). It counts every running local VM, macOS or not.
- **One driver at a time** (`flock` on `driver.lock`), so the sweeps above can never delete a
  VM that another run is using.
- No `sudo`, no host launchd change, no host file outside `--state-dir`, never the operator's
  real SSH keys (the driver is handed paths and writes nothing to them).

## SSH: key login, host key pinned

- The remote command is an argv list quoted with `shlex.join` (one string for the guest's
  zsh), never a string built from variables. The remote exit status is the wrapper's;
  255 is ssh's own failure. `-F /dev/null` ignores the user's ssh config; no agent or X11
  forwarding, no ControlMaster; `BatchMode=yes`, publickey only, `IdentitiesOnly=yes`.
- **Host key.** `HostKeyAlias=state1-vm` so the pin does not depend on the DHCP address a
  throwaway clone gets. `prep.sh` regenerates the guest's host keys once (the vanilla tag's
  keys are shared by everyone who pulls it); `golden` reads the new ed25519 key with
  `ssh-keyscan` on the private vmnet, checks a strict key login against it, and saves it to
  `known_hosts` in the state dir. Every clone carries that key, so `check` runs with
  `StrictHostKeyChecking=yes`: a changed key fails the step, it is never accepted or
  overwritten. Trust on first use (`accept-new`, scratch file deleted afterwards) is used only
  inside `golden`, before the pin exists, to a VM the driver just cloned and booted.
- **The one password login** is the vanilla image's published `admin`/`admin`, used by
  `golden` only, to install the public key. It goes through `SSH_ASKPASS` in the environment
  of that ssh process (`BatchMode` is off for it, since BatchMode disables askpass). Nothing
  secret is on a command line, and the driver logs argv only, never environments or stdin.
  `TENDCF_VM_BOOTSTRAP_PW` overrides the value.

## What each step proves

`golden` (steps g1-g10): the pinned digest clones and boots headless; the password works
once; the key installs and `sudo -n` is root; `prep.sh` ran; Python 3.14.10 installed; the new
host key is pinned and a strict key login works; **password login is refused**; the VM
stopped cleanly and was saved as `state1-golden` with a record (`golden.json`: digest, script
hashes, key fingerprints).

`prep.sh` (guest, root, idempotent, `set -eu`): snapshots `launchctl` state and the disabled
lists to `/var/db/tendcf-state1-prep/snapshots/before` (once) before touching anything, and
`after` at the end; Spotlight off (`mdutil -a -i off`); automatic update keys off; Gatekeeper on
(`spctl --global-enable`); a named list of unused launchd jobs disabled; fresh SSH host keys;
`/etc/ssh/sshd_config.d/050-tendcf-state1.conf` (no password or keyboard-interactive login),
verified with `sshd -T`. It changes nothing under `/System`, not SIP, not Recovery.

`check` (issue 70 checklist; ids as in the JSON):

| Step | What it proves | Status |
| --- | --- | --- |
| 1 | the clone boots headless, `tart ip --wait` answers, key login works on the pinned host key | live |
| 2a-2c | `sw_vers` is 27.x; SIP enabled; `sudo -n sh -c 'id -u'` is 0 | live |
| 2d-2f | Gatekeeper enabled; sshd effective config key-only; password login refused from the host | live |
| 2g-2i | Spotlight off; automatic updates off; Python 3.14.10 present, `root`-owned, not group/world writable | live |
| 3 | install path ownership and permissions of the tendcf build | **skip: needs the renderer slice** (the assertion `perm_ok`/`check_root_owned` is live; 2i applies it to the Python framework) |
| 4-9 | render as root, golden-render comparison, bootstrap and print, idempotency, drift repair, non-root negatives | **SKIP: renderer slice** |
| 10, 10a | reboot; ssh returns with a new boot time; 2a-2e and 2g-2i hold again | live |
| 10b | `launchctl print system/<label>` loads from disk at boot | **skip: renderer slice** |
| 11 | stop and delete the clone, always | live |

## Open items for the renderer slice

1. Steps 4-9 are skip results, not omissions: the render/install command (answer 6) and the
   golden render step 5 compares against are defined when the launchd renderer lands.
   `check` needs a hook to install the build under test (copy the artifact in, run the render
   command as root with `sudo -n`) between steps 2 and 10.
2. Step 3 needs the tendcf install path list; call `check_root_owned(ctx, target, path)` for
   each of the binary and the policy directory.
3. Step 10b needs the daemon label; add `launchctl print system/<label>` to the post-reboot
   assertions.

## Things this slice could not verify (no VM was run)

- The launchd disable list in `prep.sh` is a candidate list for a headless VM, applied only to
  labels whose plist ships on the image. The first real run's `before` snapshot is the
  evidence to prune it against.
- Assumed from tart's source and docs, not run: `tart list --format json` field names
  (`Name`, `Running`), `tart clone` of an `@sha256:` reference from the OCI cache without a
  pull, `tart ip --wait`, that a guest `shutdown -r` keeps `tart run` alive (if it exits, the
  driver restarts it), the macOS 27 `sshd_config.d` include, `spctl --global-enable`, and the
  `installer -pkg` run for python.org's package (its optional shell-profile step edits the
  console user's profile, which is harmless in a throwaway VM).
- The admin account still has the vanilla console password. Only SSH is key-only; a console or
  Recovery login is outside this slice's scope (the VM runs `--no-graphics`).
