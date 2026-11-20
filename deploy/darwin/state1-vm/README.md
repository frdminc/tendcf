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
(default `~/.local/state/tendcf-state1-vm`: logs, pinned `known_hosts`, `golden.json`),
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
  unless `--rebuild`, and then the old golden is deleted only at the commit, right before the
  rename (a failed build costs nothing). The commit (delete the old golden, rename, then write
  `known_hosts` and `golden.json`) runs with SIGINT/SIGTERM/SIGHUP ignored, the two record
  files are written only after the rename succeeded, and from the moment the old golden is
  touched the finished build is never deleted by cleanup: if the delete or the rename fails the
  finished build is kept, `known_hosts`/`golden.json` still describe the old golden, and the
  evidence says what to run (after a failed rename the new record is parked as
  `known_hosts.pending` and `golden.json.pending` in the state dir). A guest that does not
  halt by itself within 180 s is powered off with `tart stop`, and that **fails g10**: an image
  that may be missing its last writes is not saved (the build is removed, or kept with
  `--keep-on-failure`). A leftover `state1-golden-build` is stopped and deleted first.
  `golden` also refuses (exit 2) while **any other VM is running**: no other guest may share
  the vmnet while the host key is pinned (see SSH below). `image.json` may carry
  `vanilla_host_key` (`ssh-ed25519 <base64>`): then the bootstrap login is strict against it;
  without it the first login is trust on first use and `golden.json` records the full key line
  seen (`vanilla_host_key_seen`, with `vanilla_host_key_seen_fingerprint` beside it), which
  can be pasted into `image.json` as it is.
- **`check`** clones `state1-golden` to `state1-check-<run id>` and always deletes it, also on
  failure or on SIGINT/SIGTERM/SIGHUP. A clone left by a killed run is swept at the next start.

## Guards

- **Two-VM cap.** Before every `tart run` (including the restart after a reboot) the driver
  reads `tart list --source local --format json` and refuses when two VMs are running (Apple's
  licence allows two macOS VMs per host). It counts every running local VM, macOS or not.
  `golden` is stricter: it needs the host to itself and refuses when any VM is running.
- **One driver at a time per host** (`flock` on one fixed file,
  `~/.local/state/tendcf-state1-vm/driver.lock`, opened without following a symlink,
  whatever `--state-dir` says; the path follows `$HOME` when the driver starts, so a run under
  a different `HOME`, a sandbox or `sudo -H` takes a different lock), because the VM names (`state1-golden-build`,
  `state1-check-*`) are global in tart: a second driver with another `--state-dir` is refused,
  so the sweeps above cannot delete a VM another run is using. The cap check is
  best-effort for VMs that other tools start.
- No `sudo`, no host launchd change, never the operator's real SSH keys (the driver is handed
  paths and writes nothing to them). It writes under `--state-dir` and the lock directory;
  `--summary FILE` may write anywhere you point it, and tart itself writes `~/.tart`.
- **No host service bound to 0.0.0.0 while `golden` or `check` run.** On tart's default NAT
  the guest reaches such a service at the bridge gateway, and it runs a third-party image and
  a downloaded installer as root. tart's softnet isolation needs a setuid-root host install,
  which this slice does not make.

## SSH: key login, host key pinned

- The remote command is an argv list with every word single-quoted (one string for the
  guest's zsh, where a bare `=ls` would expand), never a string built from variables. Key and
  known_hosts paths with whitespace, `%`, `$` or a leading `~` are refused (ssh would split or
  expand them). The remote exit status is the wrapper's;
  255 is ssh's own failure. `-F /dev/null` ignores the user's ssh config; no agent or X11
  forwarding, no ControlMaster; `BatchMode=yes`, publickey only, `IdentitiesOnly=yes`.
- **Host key.** `HostKeyAlias=state1-vm` so the pin does not depend on the DHCP address a
  throwaway clone gets. `prep.sh` regenerates the guest's host keys once (the vanilla tag's
  keys are shared by everyone who pulls it) and prints the new ed25519 public key as
  `PREP-HOSTKEY ...` **inside the bootstrap session** (trust on first use, or the pinned
  vanilla key, whose private half is public: it ships in the public image, so anyone who pulls
  the digest holds it). That pin is therefore trustworthy only if no other guest is on the
  vmnet during `golden`, which is why `golden` refuses to start while any other VM runs. `golden` pins
  exactly that line under the alias straight after prep; `ssh-keyscan` is only a cross-check
  that must give the same key (any difference fails the build and pins nothing). Every
  connection after prep (Python install, password check, shutdown) and every `check` uses
  `StrictHostKeyChecking=yes` against the pinned file: a changed key fails the step, it is
  never accepted again and never `=no`. Trust on first use (`accept-new`, scratch file deleted
  afterwards, unless `image.json` pins the vanilla key) is used only before prep, to a VM the
  driver just cloned and booted. Each guest script runs in one ssh session: it is streamed on
  stdin to a `mktemp` file that the same session removes.
- **The one password login** is the vanilla image's published `admin`/`admin`, used by
  `golden` only, to install the public key. It goes through `SSH_ASKPASS` in the environment
  of that ssh process (`BatchMode` is off for it, since BatchMode disables askpass). Nothing
  secret is on a command line, and the driver logs argv only, never environments or stdin.
  `TENDCF_VM_BOOTSTRAP_PW` overrides the value.

## What each step proves

`golden` (steps g1-g10): the pinned digest clones and boots headless; the password works
once; the key installs and `sudo -n` is root; `prep.sh` ran; the host key prep printed is
pinned (keyscan agrees) and a strict key login works; Python 3.14.10 installed over that
strict login, then the whole `Python.framework` (`Versions/`, `Versions/Current` and the
top-level links included, not only `Versions/3.14`) is made `root:wheel` and checked as a
tree, and every ancestor up to `/` must be root-owned and not group/world writable
(python.org leaves `Versions/` `root:admin 775`); **password login is
refused** (the ssh method list must not offer `password` or `keyboard-interactive`); the guest
is halted with `shutdown -h now` and `tart run` exits by itself (a forced `tart stop` after
180 s is a power-off and fails g10); then it is saved as `state1-golden` with a record
(`golden.json`: digest, script hashes, key fingerprints, the vanilla key line seen).

`prep.sh` (guest, root, idempotent, `set -eu`): snapshots `launchctl` state and the disabled
lists to `/var/db/tendcf-state1-prep/snapshots/before` (once) before touching anything, and
`after` at the end; Spotlight off (`mdutil -a -i off`); automatic update keys off; Gatekeeper on
(`spctl --global-enable`); **Screen Sharing off** (`launchctl disable` + `bootout`, read back
with `print-disabled`, nothing listening on tcp 5900 (a failing or silent `netstat` is fatal too): fatal, because the vanilla image has it
on with the published admin password); a named list of unused launchd jobs disabled (read
back, a failure is reported not fatal); fresh SSH host keys;
`/etc/ssh/sshd_config.d/050-tendcf-state1.conf` (no password or keyboard-interactive login,
no root login), verified with `sshd -T`. It changes nothing under `/System`, not SIP, not
Recovery.

`check` (issue 70 checklist; ids as in the JSON):

| Step | What it proves | Status |
| --- | --- | --- |
| 1 | the clone boots headless, `tart ip --wait` answers, key login works on the pinned host key | live |
| 2a-2c | `sw_vers` is 27.x; SIP enabled; `sudo -n sh -c 'id -u'` is 0 | live |
| 2d-2f | Gatekeeper enabled; sshd effective config key-only; password login refused from the host | live |
| 2g-2i | Spotlight off; automatic updates off; Python 3.14.10 present, the whole framework `root:wheel` and not group/world writable, ancestors root-owned and not group/world writable | live |
| 2j-2k | Screen Sharing disabled (`print-disabled`), nothing listening on tcp 5900 | live |
| 3 | install path ownership and permissions of the tendcf build | **skip: needs the renderer slice** (the assertion `check_root_owned(..., tree=True)` is live: `root:wheel`, no group/world write, whole tree, and every ancestor up to `/` root-owned and not group/world writable; 2i applies it to `/Library/Frameworks/Python.framework`) |
| 4-9 | render as root, golden-render comparison, bootstrap and print, idempotency, drift repair, non-root negatives | **SKIP: renderer slice** |
| 10, 10a | reboot; ssh returns with a new `kern.bootsessionuuid`; 2a-2e and 2g-2k hold again | live |
| 10b | `launchctl print system/<label>` loads from disk at boot | **skip: renderer slice** |
| 11 | stop and delete the clone, always | live |
| 11a | bootout and remove the installed daemon; `launchctl print` then fails | **skip: renderer slice** (nothing is installed yet; only the stop-and-delete half of step 11 exists) |

## Open items for the renderer slice

1. Steps 4-9 are skip results, not omissions: the render/install command (answer 6) and the
   golden render step 5 compares against are defined when the launchd renderer lands.
   `check` needs a hook to install the build under test (copy the artifact in, run the render
   command as root with `sudo -n`) between steps 2 and 10.
2. Step 3 needs the tendcf install path list; call `check_root_owned(ctx, target, path)` for
   each of the binary and the policy directory.
3. Step 10b needs the daemon label; add `launchctl print system/<label>` to the post-reboot
   assertions.
4. Step 11a (bootout, remove, confirm `launchctl print` fails) needs the installed daemon;
   it runs before the stop-and-delete that step 11 already does.

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
- The admin account keeps the vanilla password `admin`/`admin`, **for the local console only**
  (changing it breaks the image's automatic login and login keychain). Screen Sharing is off
  (asserted before and after the reboot) and SSH is key-only, so nothing on the network accepts
  that password; the VM runs `--no-graphics`. Revisit if a later slice needs a password owner.
- Assumed from the template and docs, not run: that `launchctl disable` + `bootout` stops
  Screen Sharing on macOS 27, that `pkgutil --check-signature` prints the status and `1.` leaf
  lines the script compares, that python.org's postflight leaves `root:admin 775` (read from
  CPython's `postflight.framework`), that `kern.bootsessionuuid` exists in the guest, that
  `shutdown -h now` ends `tart run`, and that a refused password login prints
  `Permission denied (publickey).` with no password method listed.
