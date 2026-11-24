# State 1 macOS VM: image prep and check harness

Slice A of [issue 70](https://github.com/frdminc/tendcf/issues/70): the scripts that
build and check state 1's Apple Silicon macOS VM on bigmac (tart 2.42.0). It follows
the 2026-11-17 answers on the issue: the pinned vanilla image as is, SSH only, key login,
Gatekeeper on, Recovery and the 50 GB disk kept, python.org Python 3.14.10 system-wide,
no CI for this image, no guest agent, no runner. Live macOS 27.2 VM verification
passed all 25 steps on 2026-11-23 (`macos-fork-build.yml` run `45196778339`,
commit `e2811834`, closing issue #70); unit tests in `tests/darwin/test_state1_vm.py`
run hermetically against a fake `tart` and `ssh`.

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
python3 state1_vm.py golden                          # build local VM state1-golden (add --rebuild to redo)
python3 state1_vm.py check                           # image-only check (skips steps 3-9/9a/10b/11a)
python3 state1_vm.py check --tarball FILE            # full check with a local PR 95 tarball + .sha256
python3 state1_vm.py check --artifact-run RUN_ID     # full check downloading the PR 95 artifact via gh
```

Neither `golden` nor `check` takes a key or asks for anything: no key argument, no password
prompt, no operator input (see "Credentials" below). Common options: `--summary FILE` (write
the JSON there, not to stdout), `--state-dir DIR` (default `~/.local/state/tendcf-state1-vm`:
logs, pinned `known_hosts`, `golden.json`, the per-golden `keys/`), `--image FILE`. Exit
status: 0 ok, 1 a step failed, 2 refused or bad usage, 130 interrupted. `--pubkey` and
`--identity` no longer exist (they are rejected as bad usage).

- **`resolve`** reads the manifest digest for the pinned tag from the registry (an anonymous
  token and one HEAD request). It reports whether the tag has moved; the digest in
  `image.json` decides, not the tag.
- **`pull`** runs `tart pull <repo>@<digest>`. A no-op when that digest is already in the OCI
  cache. Tart's pull resumes, so re-run it after an interruption.
- **`golden`** refuses (exit 2) when the pinned image is not already in the OCI cache; it
  never pulls. It builds into `state1-golden-build` and renames to `state1-golden` last, so a
  half-built image is never the golden one. With `state1-golden` present it does nothing
  unless `--rebuild`, and then the old golden is deleted only at the commit, right before the
  rename (a failed build costs nothing). The commit runs with SIGINT/SIGTERM/SIGHUP ignored and has six steps in
  this order (four of them file writes): first an **intent owner file** (`"state": "committing"`: this state dir, the new
  key id and host key), before anything is destroyed; then delete the old golden, rename, write
  `known_hosts`, write `golden.json`, and last the **final owner file** (`"state": "final"`).
  The record files are written only after the rename succeeded, and from the moment the old
  golden is touched the finished build is never deleted by cleanup: if the delete or the rename
  fails the finished build is kept, `known_hosts`/`golden.json` still describe the old golden
  (a failed delete puts the previous owner file back; a failed rename leaves the intent one),
  and the evidence says what to run (the new record is parked as `known_hosts.pending` and
  `golden.json.pending` in the state dir and `golden-owner-<golden>.json.pending` beside the
  lock; a hand finish is `tart rename` then three `mv`, the last one making this state dir the
  owner, after which plain `golden` says "nothing to do" and `check` passes; if even parking
  fails the evidence says so and only `--rebuild` finishes it). A successful commit removes
  those three `.pending` files of an earlier unfinished commit and says so (they describe a
  build that is gone). Every write is atomic (temp file, `fsync`, rename, `fsync` of the
  directory; on macOS `F_FULLFSYNC`, falling back to `fsync`); a failed write ends the g10 step
  with the list of writes that landed, never a traceback. A write whose rename landed but whose
  directory could not be synced is reported as landed with durability unconfirmed, not as
  failed. An intent write whose directory sync fails after the rename puts the previous owner
  file back; one that fails before the rename leaves that file as it was. If the **final**
  owner file is the one that landed unsynced, the commit is complete: the step passes with a
  "durability unconfirmed" note, the cleanup runs and the run exits 0. `F_FULLFSYNC` falls
  back to plain `fsync` only when the filesystem does not support it (`ENOTSUP`,
  `EOPNOTSUPP`, `EINVAL`, `ENOTTY`); any other error, `EIO` for one, fails the write. A guest that does not
  halt by itself within 180 s is powered off with `tart stop`, and that **fails g10**: an image
  that may be missing its last writes is not saved (the build is removed by the cleanup, or
  kept with `--keep-on-failure`). A leftover `state1-golden-build` is stopped and deleted first.
  `golden` also refuses (exit 2) while **any other VM is running**: no other guest may share
  the vmnet while the host key is pinned (see SSH below). `image.json` may carry
  `vanilla_host_key` (`ssh-ed25519 <base64>`): then the bootstrap login is strict against it;
  without it the first login is trust on first use and `golden.json` records the full key line
  seen (`vanilla_host_key_seen`, with `vanilla_host_key_seen_fingerprint` beside it), which
  can be pasted into `image.json` as it is.
- **`check`** clones `state1-golden` to `state1-check-<run id>` and always deletes it, also on
  failure or on SIGINT/SIGTERM/SIGHUP. A clone left by a killed run is swept at the next start.
  It logs in with the golden's own key, found through `golden.json` (see Credentials).

## Credentials: nothing is typed by the operator

- **SSH key, one per golden.** `golden` mints a fresh ed25519 keypair
  (`ssh-keygen -t ed25519 -N ''`) for each build, under
  `<state-dir>/keys/<key id>/id_ed25519` (directory 0700, private key 0600; the key id is the
  run id). Only the public half is baked into the golden; the private key never leaves the
  host, is never committed and is never copied into `golden.json`. A rebuild mints a new key,
  never reuses one, and removes the private keys of every other golden's key id once the new
  golden is committed (a failed build removes its own key, unless `--keep-on-failure` or a
  failed rename or a failed removal of the old golden keeps the build, which needs it; the
  record naming that key is then parked as `golden.json.pending`). `golden.json` records
  `key_id` and `authorized_key` (the public key's fingerprint); `check` takes the key from
  there, under the driver lock, and refuses (exit 2) unless `keys/` and `keys/<id>/` are real
  directories (never symlinks) owned by you with no group or world access, the private key is
  a regular file owned by you with mode 0600, and the public half derived from the private key
  (`ssh-keygen -y`) matches the recorded fingerprint. A sweep that cannot remove a stale key
  reports it and fails the `keys` step. Key logins use `IdentitiesOnly=yes` and
  `IdentityAgent=none` (also on the password-mode bootstrap and refusal-probe logins), so the
  operator's ssh-agent is never contacted. `ssh-keygen -y` runs with `-P ''` and no controlling
  terminal, so a passphrase-protected key is refused, never asked about. `check` and `golden`
  share one usability test: `golden.json` parses (and has a `host_key`), `known_hosts` is
  exactly the one line the driver writes (`state1-vm ssh-ed25519 <key>`; ssh honours every line,
  pattern, hashed name, `@cert-authority` and `@revoked` entry of a file, so anything else is
  refused), that key is the record's `host_key` (a kill between the two commit writes, or a
  hand-moved `.pending` file, leaves them disagreeing), and the recorded key passes the checks
  above. `check` refuses (exit 2) on any of it before it clones anything.
  **Owner marker.** The tart golden is global to a tart home and the records are per
  `--state-dir`, so the commit writes `<passwd home>/.local/state/tendcf-state1-vm/golden-owner-<golden
  name>-<tart key>.json` beside the driver lock (`<tart key>` is the first 8 hex digits of a
  SHA-256 of the resolved tart home): the golden, the resolved state dir, the tart home,
  `key_id`, `host_key` and a `state`. The lock directory must be a real directory of yours that is not group or world
  writable, and the file is read without following a symlink (a FIFO or directory is refused,
  never waited on). The state dir (`--state-dir`, which holds the pin and the record) gets the
  same ownership and mode check (the path is resolved with `realpath` once, at startup, and
  a symlink to such a directory is the operator's choice; a missing one is made 0700, parents
  included; a path that is a file is refused, and so is a `--state-dir` that is itself a
  symlink that points nowhere or is not yours: nothing is created through it; a link
  planted after the path was resolved is not followed either). A lock directory that cannot be
  made is a refusal (exit 2) naming it; the mode checks do not consider macOS ACLs. Plain `golden` with the golden present rebuilds it unattended (when the
  usability test fails) or reports "nothing to do" **only** when the owner file is `final`, names
  this golden and this state dir (the same directory: `realpath`, else `samefile`) and agrees
  with this state dir's `golden.json` (`key_id`, `host_key`). Because the intent file is written
  before the first destructive step and the final one last, an agreeing final file means the last
  commit to touch this golden finished, and it was ours. Otherwise plain `golden` exits 2 and
  replaces nothing: another `--state-dir`'s golden (the message names the owner and says that a
  rebuild breaks its logins), a golden with **no record** here, an **intent** file (a commit
  that did not finish: whichever of the old and new build the golden is, nobody may bless it),
  a **missing** owner file, or a file that disagrees with the record. `golden --rebuild` always
  replaces and makes this state dir the owner. A moved or renamed state dir is a different
  owner. **The tart home** is resolved once, at startup, the way tart does it: `TART_HOME` if
  set (even empty, which tart takes as the current directory; made absolute with `realpath`),
  else `CFFIXED_USER_HOME` (set but empty is the current directory, as in Foundation), else
  the passwd home, plus `/.tart`; `$HOME` is never consulted (tart ignores it), except for a
  uid with no passwd entry (a container), where Foundation falls back to it too. The driver exports that value as `TART_HOME` to every `tart` command it
  runs, so tart and the driver cannot disagree. The lock and the marker live under the passwd
  home: one lock per account (see Guards), and one marker per tart home (named by the tart
  key), and a different `HOME`, a sandbox or `sudo -H` for the same user takes the same ones.
  The marker is keyed, the state dir is not: a state dir is not meant to be shared across
  tart homes (one `golden.json` can describe one golden), so use one `--state-dir` per tart
  home. A run under another
  tart home finds no marker of its own, so plain `golden` exits 2 (a missing owner file); a
  marker copied or forged under that name that records another tart home is refused naming it
  (and so is `check`). An owner file of an earlier build of this change (named without the
  tart key) is simply not found and is ignored, never trusted; a keyed one without a
  `tart_home` field is refused (exit 2) with that reason and one `golden --rebuild` writes it.
  A `state_dir` in the marker that is not an absolute printable path (a relative path, or one
  with control characters) is a torn or forged marker (exit 2; it is never stat'ed, and only
  printed in `repr` form). Plain `golden` also re-checks the owner at the start of the commit,
  and again at the delete: a golden that was not there at the re-check and is there
  at the delete (a hand `tart rename`, a driver under another tart home) is not deleted
  without `--rebuild`; the finished build is kept (no records are parked, so it cannot be
  finished by hand), the owner file stays `committing`, so plain `golden` exits 2 until
  `golden --rebuild` sweeps the kept build and builds afresh, and the run exits 1. The remaining unattended deletion is the case where the owner file already
  names this state dir (a final file that agrees with the record) but the usability test
  fails: that golden is ours and is replaced.
  **Upgrade note:** run `golden --rebuild` once after upgrading: an older driver's
  `golden --rebuild` from another state dir can leave the new marker agreeing with this state
  dir's record. A golden built before owner files existed (or whose owner file is the
  older unkeyed one) has none, so the first plain
  `golden` after upgrading exits 2 until one `golden --rebuild` writes it; `check` does not need
  the marker and still passes. (Letting a passing `check` write the missing marker is tracked as
  [issue 81](https://github.com/frdminc/tendcf/issues/81).) `check` reads the marker too: a
  **final** file naming another state dir, another tart home or another key exits 2 early,
  naming it; a `committing` file of another state dir (its commit did not finish: the golden is
  the old or the new build) does not refuse, the login decides and the evidence says so; a
  missing one is ignored. Paths printed inside a suggested command are shell-quoted. Its hints say what is true for the case at hand (`golden` for an owner,
  `golden --rebuild` where plain `golden` would refuse, and never `--rebuild` over another
  state dir's golden without naming it). What still needs a human: a `keys/` or `keys/<id>/`
  directory with group or world access (or a symlink, or another owner), a lock directory or
  state dir that is group or world writable (fix with `chmod`), a commit that did not finish
  and a golden from before owner files (one `golden --rebuild` each). Remove a bad `keys/`
  directory or `chmod 700` it. The driver never reads or offers anything in the operator's own `~/.ssh`.
- **The bootstrap login** is the one password login, and no operator provides it: it is the
  vanilla image's published `admin`/`admin`, used once by `golden` to install that public key
  (see SSH below).
- **Console password, random and not stored.** The vanilla `admin` password is the published
  `admin`. `prep.sh` replaces it with 32 random alphanumerics made inside the guest, sets it
  with `dscl . -passwd`, proves it with `dscl . -authonly`, proves the vanilla one no longer
  authenticates, and then unsets it. It is never printed, never written to a file in the
  guest, and never sent to the host; nothing needs it afterwards (SSH is key-only, `sudo` is
  `NOPASSWD`, Screen Sharing is off and asserted). `prep.sh` prints one `PREP-CONSOLE-PW
  rotated` line and the driver fails g6 unless that line appears exactly once; `golden.json`
  says `console_password` is "random per golden, set in the guest, never stored". On the first
  run the vanilla password still authenticates, so `prep.sh` uses the old-and-new form
  (`dscl . -passwd /Users/admin admin "$pw"`), which is expected to keep a Secure Token account in step (unverified; see "could not verify"); the form used is logged;
  the root form without the old password is only the re-run fallback. Consequences, by design: local console login and
  the login keychain are unusable, and the `/etc/kcpassword` the vanilla image's autologin
  uses is stale (it holds the old password, XOR-obfuscated); `prep.sh` leaves both alone. If a
  later slice needs the console password, that is a new decision, not something to read back
  from here.

## Guards

- **Two-VM cap.** Before every `tart run` (including the restart after a reboot) the driver
  reads `tart list --source local --format json` and refuses when two VMs are running (Apple's
  licence allows two macOS VMs per host). It counts every running local VM, macOS or not.
  `golden` is stricter: it needs the host to itself and refuses when any VM is running.
- **One driver at a time per account** (`flock` on one fixed file,
  `<passwd home>/.local/state/tendcf-state1-vm/driver.lock`, opened without following a
  symlink, whatever `--state-dir` and the tart home say; the path follows the passwd home, not
  `$HOME`, so a run under a different `HOME`, a sandbox or `sudo -H` takes the same lock, and
  an older driver and this one exclude each other when `$HOME` is the passwd home), because
  the VM names (`state1-golden-build`,
  `state1-check-*`) are global in tart: a second driver with another `--state-dir` is refused,
  so the sweeps above cannot delete a VM another run is using. The cap check is
  best-effort for VMs that other tools start.
- No `sudo`, no host launchd change, never the operator's real SSH keys (the driver is not
  handed any and reads none; it mints its own, see Credentials). It writes under `--state-dir` and the lock directory;
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
  `golden` only, to install the golden's public key. It is public knowledge, not a secret and
  not operator input. It goes through `SSH_ASKPASS` in the environment
  of that ssh process (`BatchMode` is off for it, since BatchMode disables askpass). Nothing
  secret is on a command line, and the driver logs argv only, never environments or stdin.
  `TENDCF_VM_BOOTSTRAP_PW` overrides the value (only for a vanilla image that ships a
  different default; nothing sets it today).

## What each step proves

`golden` (steps g1-g10): the pinned digest clones and boots headless; the bootstrap password
works once; the golden's own freshly minted key installs and `sudo -n` is root; `prep.sh` ran
(including the console password rotation); the host key prep printed is
pinned (keyscan agrees) and a strict key login works; Python 3.14.10 installed over that
strict login, then the whole `Python.framework` (`Versions/`, `Versions/Current` and the
top-level links included, not only `Versions/3.14`) is made `root:wheel` and checked as a
tree, and every ancestor up to `/` must be root-owned and not group/world writable
(python.org leaves `Versions/` `root:admin 775`); **password login is
refused** (the ssh method list must not offer `password` or `keyboard-interactive`); the guest
is halted with `shutdown -h now` and `tart run` exits by itself (a forced `tart stop` after
180 s is a power-off and fails g10); then it is saved as `state1-golden` with a record
(`golden.json`: digest, script hashes, `key_id`, key fingerprints, the vanilla key line seen,
`console_password: never stored`); a key from an earlier golden is removed at that commit.

`prep.sh` (guest, root, idempotent, `set -eu`): snapshots `launchctl` state and the disabled
lists to `/var/db/tendcf-state1-prep/snapshots/before` (once) before touching anything, and
`after` at the end; Spotlight off (`mdutil -a -i off`, then `mdutil -a -s` read back via a
root-only `mktemp` file under `$STATE_DIR` preserving exit status and NUL bytes, mapped `\000` ->
`\001` once with `LC_ALL=C tr`:
`Indexing enabled` anywhere is fatal at once; `kMDConfigSearchLevelTransitioning` anywhere is
retried every 2 s until 120 s (tracked via `$SECONDS` in macOS `/bin/sh` = bash 3.2, with
printed elapsed seconds clamped at `>= 0`) or 65 polls (120 / 2 + 5 margin, which stops the loop
after 65 polls — about 130 s plus mdutil's own time — if the clock steps backwards), whatever
mdutil's exit status (that status was never
recorded); then a non-0 exit is fatal; then any line holding a control character other than tab
(NUL included, via the `\001` mapping) fails as unexpected, and the answer must be volume
headers (a line starting with `/`, ending in `:`, and containing no tab), each followed by
exactly one `Indexing disabled.` line, with `/:` and
`/System/Volumes/Data:` among them, and
nothing else); automatic download and install off (the five keys prep writes through `defaults`,
`SplatEnabled` (believed to be the Background Security Improvements switch: inferred, not
documented by Apple) included, must each read back as 0 with a 0
exit; that softwareupdated obeys them is not observed; `com.apple.commerce AutoUpdate` is written
but not read back; automatic *checking* is not touched, see "Known limitation" below;
`softwareupdate --schedule` is run once, its text is logged for information only with CR and
newline flattened, bytes outside printable ASCII replaced with `?`, and cut at 200 bytes under
`LC_ALL=C` so the cut cannot split a multibyte character, and only a non-0 exit is fatal); Gatekeeper on
(`spctl --global-enable`); **Screen Sharing off** (`launchctl disable` + `bootout`, read back
with `print-disabled`, nothing listening on tcp 5900 (a failing or silent `netstat` is fatal too): fatal, because the vanilla image has it
on with the published admin password); a named list of unused launchd jobs disabled (read
back, a failure is reported not fatal); fresh SSH host keys;
`/etc/ssh/sshd_config.d/050-tendcf-state1.conf` (no password or keyboard-interactive login,
no root login), verified with `sshd -T`; the console password for `admin` replaced by a random
one that is proved and dropped (Credentials above). It changes nothing under `/System`, not SIP, not
Recovery.

`check` (issue 70 checklist; ids as in the JSON):

| Step | What it proves | Status |
| --- | --- | --- |
| 1 | the clone boots headless, `tart ip --wait` answers, key login works on the pinned host key | live |
| 2a-2c | `sw_vers` is 27.x; SIP enabled; `sudo -n sh -c 'id -u'` is 0 | live |
| 2d-2f | Gatekeeper enabled; sshd effective config key-only; password login refused from the host | live |
| 2g | Spotlight indexing off: `sudo -n mdutil -a -s`, stdout and stderr together, read untranslated (`raw_newlines=True`, no text mode). Per poll: `Indexing enabled` anywhere fails at once; `kMDConfigSearchLevelTransitioning` anywhere is asked again every 2 s whatever the exit status, for about 120 s plus one command (the driver counts real time between polls); then a non-0 exit fails; then any line holding a control character other than tab (CR, FF, VT, NUL, other C0, DEL) fails as unexpected, and the answer must be volume headers (a line starting with `/`, ending in `:`, and containing no tab), each followed by exactly one `Indexing disabled.` line, `/:` and `/System/Volumes/Data:` among them, and nothing else (`prep.sh` applies the same rule including NUL, via a root-only `$STATE_DIR` `mktemp` file + `LC_ALL=C tr` before `LC_ALL=C awk`). Accepted trade-off: because macOS volume names may contain spaces and colons, a space-joined `/...:` line still matches the header grammar (while `Indexing enabled` and `kMDConfigSearchLevelTransitioning` remain checked across the full output first). Lines split on `\n` only. The evidence carries every poll's exit status and ends `polls=N waited=Ns` | live |
| 2h | automatic download and install keys off: the five keys `prep.sh` writes (`AutomaticDownload`, `AutomaticallyInstallMacOSUpdates`, `ConfigDataInstall`, `CriticalUpdateInstall`, `SplatEnabled`) each read 0 with exit 0 through `defaults read`, and `sudo -n softwareupdate --schedule` exits 0. The rc-0 rule only shows that softwareupdate still runs; it says nothing about updates being off. The schedule text (stdout and stderr together) is evidence only, shown as `schedule (info): rc N: '...'`, and never decides: on macOS 27.2 it says `turned on` (see "Known limitation"). A key that does not read 0, a read error or a non-0 exit fails; the evidence shows the exit status, marks a value read only from stderr (`Key=stderr '...'`), and clips each value. The keys persist; that softwareupdated obeys them is not observed. `AutomaticCheckEnabled` is not read, and neither is `com.apple.commerce AutoUpdate` (written only) | live |
| 2i | Python 3.14.10 present, the whole framework `root:wheel` and not group/world writable, ancestors root-owned and not group/world writable | live |
| 2j-2k | Screen Sharing disabled (`print-disabled`), nothing listening on tcp 5900 | live |
| 2l | the vanilla console password `admin` no longer authenticates: `dscl . -authonly admin admin` (no sudo) must exit non-zero with exactly the wrong-password code `-14090 eDSAuthFailed`; any other code (account disabled, password expired), several codes, no code, or ssh's 255 fails the step (`prep.sh` applies the same rule; a missing user also prints `-14090 eDSAuthFailed` on macOS 27.2, observed, so this step does not prove the account exists, the key login as `admin` does) | live |
| 3 | stage bundle, run `deploy/darwin/tendcf-install.sh install` as root, and verify `check_root_owned(..., tree=True)` on `/opt/tendcf` and `<workdir>/inputs`, `root:wheel 600` on `host_specific.json`, and no `com.apple.quarantine` | live (with `--tarball` or `--artifact-run`; skipped without an artifact) |
| 4-9 | render as root (`run-once`, `root:wheel 0644`, `plutil -lint`, no `.cf-before-edit`), byte-compare against committed golden `tests/policy/golden/launchd/system/com.tendcf.canary.main.plist`, `launchctl print` + `kickstart -k`, idempotent re-run (`run-once` + installer `no change`), one-key drift edit repaired and reloaded, non-root negatives (installer, `cf-agent`, `launchctl bootstrap system`) | live (with `--tarball` or `--artifact-run`) |
| 9a | `tendcf-install.sh enable` (and idempotent re-run `no change`), `org.tendcf.execd` plist `root:wheel 0644` + `plutil -lint`, loaded and running as `root` (`launchctl print` + `ps`) | live (with `--tarball` or `--artifact-run`) |
| 10, 10a | reboot; ssh returns with a new `kern.bootsessionuuid`; 2a-2e and 2g-2l hold again (2h's rule is the same after the reboot; a passing 10a names 2g's own `polls=N waited=Ns` after the reboot — values the driver returns, not text read back from the guest's output — plus a clipped copy of the post-reboot `mdutil -a -s` listing) | live |
| 10b | post-reboot `launchctl print` for `com.tendcf.canary.main` and `org.tendcf.execd` (loaded from disk at boot; `org.tendcf.execd` running as `root`) | live (with `--tarball` or `--artifact-run`) |
| 11 | stop and delete the clone, always | live |
| 11a | canary tombstone teardown (`data` + `run-once`, plist removed, `launchctl print` fails) and `org.tendcf.execd` `disable` (plist removed, `launchctl print` fails) before step 11 | live (with `--tarball` or `--artifact-run`) |

## Known limitation: automatic update checking stays on

Operator ruling, 2026-11-21: 2h promises automatic download and install off only; checking stays
on and is documented. On macOS 27.2 (26B123) four root-script methods did not turn automatic
update *checking* off, so `softwareupdate --schedule` says `Automatic checking for updates is
turned on`; `softwareupdate -l` keeps working. The System Settings "Check for updates" toggle in a
GUI session is untried, and so is an MDM-managed Mac (Apple removed the MDM `com.apple.SoftwareUpdate`
payload in 27.0, and the declarative software update settings have no check key). The evidence
summary per method (addendum 4 of issue 70, each method on a fresh clone of the golden, read at 0,
30 and 90 s and after a reboot, 24 snapshots in all) is in PR 90:

- **A, `softwareupdate --schedule off`:** exits 0, prints the unchanged status, and does not touch
  the plist file. Run 3's `golden --rebuild` died on exactly this read-back.
- **B, `defaults write ... AutomaticCheckEnabled -bool false`:** reads back 0 and was still there
  at 30 s; it was gone at the 90 s read, in one run. The plist was rewritten (641 to 610 bytes)
  within about a second of the 30 s read's own `softwareupdate --schedule` call, so that call may
  be the trigger rather than a timer. The writer is softwareupdated or cfprefsd on its behalf,
  not proven which. `killall cfprefsd` ran; `launchctl kickstart` was refused (SIP, rc 150), so it
  never ran.
- **C, a hand-written `/Library/Managed Preferences/com.apple.SoftwareUpdate.plist`:** ignored by
  `softwareupdate --schedule` and by a merged `defaults read`. The cause is unproven; the MDM
  payload's removal in 27.0 is the likely one.
- **D, `launchctl disable` plus `bootout` of `com.apple.softwareupdated`:** `bootout` was refused
  (SIP, rc 150); `disable` was accepted (listed as disabled) but the daemon was still running after
  a reboot, and the schedule was unchanged.

What is shown for downloads and installs: `AutomaticDownload`, `AutomaticallyInstallMacOSUpdates`,
`ConfigDataInstall` and `CriticalUpdateInstall` read 0 in all 24 addendum-4 snapshots, so they
persist through the golden's shutdown, a clone and a reboot. `SplatEnabled` (believed to be the
Background Security Improvements switch: inferred, not documented by Apple) was `true` in those
snapshots (the golden was built before prep wrote it); prep now writes it false (operator ruling
2026-11-21) and 2h reads it. In issue 70 run 4 on macOS 27.2 (head `c5cc21c`), a written
`SplatEnabled false` persisted from the golden build to a fresh clone and again after the 10a
reboot (all five keys passed 2h and 10a; the driver does not record 10a's per-key values on a
pass, so 10a rests on the pass rule). Not shown: that softwareupdated obeys any of these keys
(an update, macOS 27.2.1, was still listed on offer after each reboot in addendum 4; no installed
version was read), and anything about `com.apple.commerce AutoUpdate`, which prep writes but
nothing reads back.

Issue 89 item 1 (what `softwareupdate --schedule off` prints and whether it persists) is answered:
on 27.2 it prints the unchanged status and changes nothing; the "turned off" read-back string was
never observed.

## Status errata: renderer slice hooks

Items 1-3 below are wired into `state1_vm.py check` when `--tarball FILE` (with `.sha256`) or `--artifact-run RUN_ID` is passed (unit-tested against the fake target in `tests/darwin/test_state1_vm.py`; live macOS 27.2 VM verification passed all 25 steps on 2026-11-23 against `macos-fork-build.yml` run `45196778339` at commit `e2811834`, closing issue #70):

1. Steps 3 and 4-9: `check` stages the PR 95 tarball, `.sha256`, `deploy/darwin/tendcf-install.sh`, `policy/`, and `deploy/darwin/canary/` into the guest over pinned SSH, installs as root, checks `/opt/tendcf` and `<workdir>/inputs` with `check_root_owned(..., tree=True)`, renders `com.tendcf.canary.main`, byte-compares against `tests/policy/golden/launchd/system/com.tendcf.canary.main.plist`, exercises `launchctl print`/`kickstart -k`, idempotency, drift repair, non-root negatives, and `org.tendcf.execd` (step `9a`).
2. Step 10b: verifies both `com.tendcf.canary.main` and `org.tendcf.execd` load from disk after reboot (`org.tendcf.execd` running as `root`).
3. Step 11a: applies the canary tombstone (`host_specific-absent.json` + `run-once`), runs `tendcf-install.sh disable` for `org.tendcf.execd`, and confirms `launchctl print` fails for both before step 11 deletes the clone.

## Things not yet verified, and what the real runs observed (2026-11-21)

- The launchd disable list in `prep.sh` is a candidate list for a headless VM, applied only to
  labels whose plist ships on the image. The first real run's `before` snapshot is the
  evidence to prune it against.
- **Observed on the first real run (2026-11-21, macOS 27.2 build 26B123, OpenSSH_10.5p1,
  LibreSSL 3.3.6; golden steps g1-g5 passed, g6 failed on this):** `sshd -T` prints its option
  names in CamelCase (`PasswordAuthentication no`, `KbdInteractiveAuthentication no`,
  `PubkeyAuthentication yes`, `PermitRootLogin no`, `UsePAM yes`), not the lowercase of stock
  OpenSSH. `prep.sh` (`LC_ALL=C grep -qixF`: whole line, ignoring case) and check 2e (and its
  post-reboot repeat, 10a) accept the same lines: the driver reads sshd's bytes untranslated
  (`raw_newlines`: no text mode, so Python does not turn a lone CR or CRLF into a newline),
  splits on `"\n"` only, strips nothing and folds ASCII case only, so padding or a line
  smuggled in through a quoted value (for example a `Banner` holding a form feed) does not
  count. Any CR anywhere in the output fails 2e outright, with the reason in the evidence
  (grep sees a CR as part of its line, so `prep.sh` rejects the same outputs). The
  `/etc/ssh/sshd_config.d` include is honoured (`sshd_config:19` has `Include
  /etc/ssh/sshd_config.d/*`; Apple's own `100-macos.conf` is the only other drop-in and sorts
  after ours), and the effective configuration, as `sshd -T -C user=admin,host=localhost,
  addr=127.0.0.1` prints it, was key-only; the live refusal of a password login (g9, 2f) has not
  run. The same run confirmed that `tart clone` of the `@sha256:` reference works from the
  cache, `tart ip --wait` answers, and that the vanilla image's Secure Token is enabled for
  `admin`. (Run 2, below, ran the rotation.)
- **Observed (macOS 27.2 26B123), run 2 on the merged sshd fix (2026-11-21):** `golden` passed
  g1-g10, so the CamelCase fix works on the real guest and the rotation ran. `check` failed on
  two things (2h and 10a), diagnosed on a clone of the golden:
  - **`AutomaticCheckEnabled` does not survive a raw `defaults write`.** `prep.sh` wrote it and
    read it back as 0, but the golden's `com.apple.SoftwareUpdate.plist` had no such key
    afterwards (the other four keys were there), nothing on the clone rewrote the file (mtime
    unchanged over 300 s), and `softwareupdate --schedule` printed `Automatic checking for
    updates is turned on`. PR 88's `softwareupdate --schedule off` did not work either (run 3,
    addendum 4); see "Known limitation".
  - **`mdutil -s` can say `kMDConfigSearchLevelTransitioning`**, three volumes at once
    (`Error: unexpected indexing state.  kMDConfigSearchLevelTransitioning`), when read right
    after the check's reboot. A first boot of a clone never showed it (0 to 300 s after ssh
    came up: always `Indexing disabled.`). Whether, and for how long, it appears after a
    reboot is what 10a's `waited=` now measures.
  - Also, **Secure Token (issue 78), in part:** on a clone of the rotated golden,
    `sysadminctl -secureTokenStatus admin` says `Secure token is ENABLED for user Managed via
    Tart`, so the old-and-new `dscl` form did not strip it. `prep.sh` now logs that status
    after the rotation (`secure token status (after): ...`) and the driver carries the line
    into g6's evidence. Still unverified: that the volume-owner/FileVault credential followed
    the new password.
- Assumed from tart's source and docs, not run: `tart list --format json` field names
  (`Name`, `Running`), that a guest `shutdown -r` keeps `tart run` alive (if it exits, the
  driver restarts it), `spctl --global-enable`, and the `installer -pkg` run for python.org's
  package (its optional shell-profile step edits the console user's profile, which is harmless
  in a throwaway VM).
- Console password (operator ruling 2026-11-21, replacing the earlier "keep the vanilla
  password"): the admin password is random per golden and not stored; the admin account is
  for the local console only, and Screen Sharing is off (asserted before and after the reboot)
  and SSH is key-only, so nothing on the network or console path is usable. Assumed, not run:
  that `dscl . -passwd /Users/admin admin NEW` works on macOS 27 (and, only as the re-run
  fallback, the root form), that `dscl . -authonly` prints a `-14090`/`eDSAuthFailed` result in
  one of the two shapes the driver parses (`(-14090, eDSAuthFailed)` or `DS Error: -14090
  (eDSAuthFailed)`; anything else fails closed) and that it works for the admin user without
  `sudo`, that the password in `dscl`'s argv (it is there for two commands) is visible
  only inside the throwaway guest, and that changing it leaves the guest booting and SSH working
  (the login keychain and `/etc/kcpassword` are left stale on purpose). **Secure Token:** the
  vanilla `admin` is a Secure Token holder (the first run's `before` snapshot logged it
  ENABLED); whether the change also updates the APFS
  crypto-user credential (volume owner, FileVault and Recovery unlock) is unverified, and 2l
  proves only the Directory Services password. `prep.sh` records `sysadminctl -secureTokenStatus
  admin` in the `before` snapshot and logs it (and, since run 2, again after the rotation), and
  changes nothing about the token; run 2 saw it still ENABLED after the rotation (issue 78, in
  part: see the run 2 bullet above).
- Assumed from the template and docs, not run: that `launchctl disable` + `bootout` stops
  Screen Sharing on macOS 27, that `pkgutil --check-signature` prints the status and `1.` leaf
  lines the script compares, that python.org's installer leaves `Python.framework/Versions`
  and the tree `root:admin 775` (read from CPython's `build-installer.py` "Fix file modes" and
  `postflight.framework`; the installed modes are unverified, which is why the fix-up and the
  assertion cover the whole framework and every ancestor), that `stat -f '%N %Su:%Sg %Lp'` and
  `netstat -an -p tcp` print the BSD shapes the driver and `prep.sh` parse, that `kern.bootsessionuuid` exists in the guest, that
  `shutdown -h now` ends `tart run`, and that a refused password login prints
  `Permission denied (publickey).` with no password method listed.
