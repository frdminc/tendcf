# Root-owned tendcf install (linux-targets.md step 7)

The shape is CFEngine's own: root-owned binaries and policy, work directory
under the same tree, and a root `cf-execd` that runs `cf-agent` on its schedule. No
sudoers rule is left behind; the one privileged session below does all of it.
Why this and not a `NOPASSWD` rule or an unprivileged agent: an unprivileged
`cf-agent` cannot write `/etc/systemd/system`, and a passwordless root run is
only safe when the binary, the policy and the CMDB data are all root-owned,
at which point the schedule does the job without sudo. The sources are in
the step 7 row of `docs/architecture/linux-targets.md`.

What lands on the host:

| Path | Owner | Content |
| --- | --- | --- |
| `/opt/tendcf` | root:root, no group/other write | the CI-built CFEngine fork (`--prefix=/opt/tendcf`), plus `share/tendcf/{policy,deploy,REVISION}` |
| `/opt/tendcf/var/cfengine` | root | the work directory a `--prefix` source build compiles in: keys (0700), `inputs/`, `data/` (0700), state |
| `/opt/tendcf/var/cfengine/inputs/{promises.cf,tendcf/}` | root | the entry policy and the generic bundle, copied by the installer |
| `/opt/tendcf/var/cfengine/data/host_specific.json` | root, 0600 | the CMDB data: `deploy/linux/canary/host_specific.json`, a projection of the canary goal file |
| `/etc/systemd/system/tendcf.canary.service` | root | rendered by the policy: `sleep infinity` as `nobody`, `Restart=on-failure` |
| `/etc/systemd/system/tendcf-execd.service` | root | stage B only: runs `cf-execd --no-fork` |

The canary is the "one stateless service": it does nothing and is removed by
its own tombstone.

## Stage A: install, enforce once, look

From a checkout with `gh` access to frdminc/tendcf. `RUN` is a green `Linux`
run on the commit you want (its `debian-13` job uploads the artifact):

```sh
gh run download RUN -R frdminc/tendcf -n cfengine-fork-debian13
scp cfengine-fork-debian13-x86_64.tar.gz pastebin.xvm.mit.edu:/tmp/
ssh -t pastebin.xvm.mit.edu
```

On pastebin (each `sudo` asks for the password once):

```sh
sudo tar -C /opt -xzf /tmp/cfengine-fork-debian13-x86_64.tar.gz --no-same-owner
cat /opt/tendcf/share/tendcf/REVISION            # the tendcf commit this bundle is
T=/opt/tendcf/share/tendcf/deploy/linux
sudo $T/tendcf-install.sh install --data $T/canary/host_specific.json
sudo $T/tendcf-install.sh run-once               # the first enforcing run
systemctl status tendcf.canary.service           # active, enabled, User=nobody
sudo $T/tendcf-install.sh status
```

`install` refuses a binary that loads a library from outside `/opt/tendcf` and
the system library directories, and rejects data `cf-promises` does not accept
(restoring the previous file). `run-once` is `cf-agent -K -I` over the
installed `promises.cf`; run it again and it prints no repairs.

## Stage B: let cf-execd run it

Only after stage A looks right:

```sh
sudo $T/tendcf-install.sh enable                 # tendcf-execd.service, every 5 minutes
```

## Roll back and remove

```sh
sudo $T/tendcf-install.sh data $T/canary/host_specific-absent.json
sudo $T/tendcf-install.sh run-once               # the tombstone removes tendcf.canary.service
sudo $T/tendcf-install.sh disable                # stage B off
sudo rm -rf /opt/tendcf                          # everything the install made but the units (removed above)
```

## Proof before the host

`tests/deploy/linux-install.sh` runs this whole sequence, stages A and B and the
tombstone, as root on the GitHub ubuntu VMs (real systemd as PID 1), including
a `cf-execd --once` that puts a stopped canary back. It writes only under
`/opt/tendcf` and `/etc/systemd/system`. `deploy/linux/canary/check.py` keeps the canary goal
files schema-valid and their projections byte-identical.
