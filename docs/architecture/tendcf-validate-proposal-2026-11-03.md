# `tendcf-validate`: options for map §12's open items 1-8 (proposal)

**Date:** 2026-11-03 (written 2026-11-02 against `master` at `95b5ab0`,
after schema v5 landed). **Author:** Claude Opus 5.5 (validate-design
slice). **Status: a proposal. It decides nothing.** Every item below is
open until djbclark rules on it. Nothing here amends the map, a schema,
a ruling or any code. Where this document recommends reopening an earlier
ruling (item 8, R4), it says so; that remains djbclark's decision.

Authority it works under: [`architecture-DEFINITIVE-v3.md`](architecture-DEFINITIVE-v3.md)
D45 and map §12's "Open, for the operator" list; map §9 (the validator,
§9.1 baseline and DC-2, §9.6 fail closed, §9.8 privilege and DC-11, §9.11
TUF); map §11 (timeout is deny); [`change-process.md`](change-process.md)
§3; [`upstream-overlay.md`](upstream-overlay.md) §2; residues R22 and R24
of [`projector-reconciliation-2026-08-16.md`](projector-reconciliation-2026-08-16.md).

How the CFEngine claims were checked: the fork source at the commit
`overlay/fork.json` pins (`b8abf28408b1b54e285d372a9bc5f2d850c960ad`,
read with `git show` in `~/src/cfengine-core`). The book (*Learning
CFEngine*, 3.12) was searched first. It covers cf-execd's role and five-minute
default schedule (ch. 23) and `cf-runagent` (ch. 35). `book-kb query`
finds neither `host_specific` nor `exec_command` in it: both postdate or
fall outside the book, so every claim about them rests on the source.

## 0. Facts every option below relies on

Each was read in the pinned fork source or in this repository on
2026-11-02. Line numbers are at the pinned commit.

1. **CFEngine has no gate on `host_specific.json`.** `LoadCMDBData`
   (`libpromises/cmdb.c`) returns success when the file is absent
   ("not an error"). `GenericAgentDiscoverContext`
   (`libpromises/generic_agent.c:1234`) logs a failed load ("Failed to
   load CMDB data") and the run continues. `cf-agent
   --no-host-specific-data` skips the load entirely.
2. **On the pinned fork, a bad entry is skipped on its own, not with the
   whole file.** `ReadCMDBVars` `continue`s past an entry carrying an
   unexpanded variable reference or an invalid key, and still installs
   the others. The cause is fork commit `8f0076b81` ("Fixed one bad CMDB
   entry discarding every entry in its section"), merged into
   `tendcf-integration` on 2026-10-29. So a projection with a bad
   `tendcf_interlock` container still loads `tendcf_service`. In
   `policy/tendcf_services.cf`, the only source of the
   `interlock_blocked_*` classes is the interlock container (lines
   107-147). Services are gated *negatively*, on
   `!interlock_blocked_<bundle>` (lines 217, 280, 313). A skipped or
   missing `tendcf_interlock` container therefore leaves every service
   ungated: **fail-open, in the live design**. The skip is a whole
   top-level `vars` key, and so a whole container: `AddCMDBVariable`
   installs a container as one value. `ReadCMDBVars` still returns
   `true` (`cmdb.c:380`), so not even "Failed to load CMDB data" is
   logged. A check made before publication (the projector's N-series)
   prevents the causes it knows about. It cannot prove that the loader
   accepts what the projector accepted. The remedies are in §13, for the
   operator.
3. **No data means no actuation, and no removal either.** The generic bundle
   iterates `getindices("data:variables.tendcf_service")`. With no CMDB
   data it promises nothing, so it removes nothing: tombstones live in
   the data. Withholding the projection therefore freezes the host's
   managed services in whatever state they are in. It neither converges
   them nor rolls them back.
4. **cf-execd runs `exec_command` through a shell and discards its
   exit status.** `cf-execd/cf-execd-runner.c:239` calls
   `cf_popen_sh(esc_command, "r")`, so `a && b` in `exec_command` works.
   The output goes to `$(sys.workdir)/outputs/` and to mail if
   configured. `cf_pclose(pp)` at line 384 ignores the return value: a
   non-zero exit is invisible except through what the command prints.
5. **The cf-execd timeout kill targets one child of the popen'd process,
   and that child's process group only if the child leads one.** On
   `agent_expireafter` (default 120 minutes, `exec-config.c:138`), the
   runner lists the children of the process `cf_popen_sh` started
   (`pid_shell`) and signals the first one. It signals that child's
   whole group only when the child's PGID equals its PID
   (`cf-execd-runner.c:284-314`). The signal sequence is SIGINT, then
   SIGTERM after 1 s, then SIGKILL after 5 s more
   (`ProcessSignalTerminate`, `libpromises/unix.c`). Which process is
   picked depends on whether `sh -c` `exec`s a single simple command,
   which this review did not verify for the hosts' `/bin/sh`.

   - If the shell stays, the picked child is the wrapper.
   - If the shell `exec`s, `pid_shell` is the wrapper and the picked
     child is cf-agent.

   This proposal's first text had the wrapper call `setpgid(0,0)`. That
   is wrong in the second case. cf-agent would inherit the wrapper's
   group, so it does not lead a group, and only its own PID is signalled.
   Its children are left alive, and the wrapper wakes up and carries on
   with its post-run steps (review finding 1).

   Two more facts bear on the protocol in §1:

   - The pinned build is configured with `--enable-debug`
     (`.github/actions/build-fork/action.yml:54`), so
     `assert(procs->next == NULL)` (`cf-execd-runner.c:302`) is live:
     a `pid_shell` with two children aborts the timeout path.
   - A `commands:` promise with `exec_timeout` runs in its *own*
     process group (`pipes_unix.c:243-258`). No group kill from above
     reaches it, so it outlives a SIGKILLed cf-agent. That is CFEngine's
     behaviour with or without a wrapper.
6. **cf-execd loads the file too**, at start and at policy reload
   (`cf-execd.c:194`, `:1001`), as map §12 says. It is harmless while
   the projection carries supervision vars only (P-1).
7. **The fork has `--simulate-json`** (`cf-agent/cf-agent.c:189`) and
   `hashmatch()` (`libpromises/evalfunction.c`).
8. **Today's Linux install** (`deploy/linux/tendcf-install.sh`): root
   cf-execd, `exec_command => "$(sys.cf_agent) -f
   $(sys.inputdir)/promises.cf"` (line 137). The projection is installed
   by `put_data` with `install -m 0600`, then `cf-promises` checks it,
   and on refusal the previous file is restored. `put_data` writes the
   destination path itself, not a temporary file renamed into place, so a
   cf-agent starting during `put_data` can read a partly written or
   rejected file. The install also has a second launch path:
   `run-once` (`cf-agent -K -I`) bypasses cf-execd.
9. **NixOS today** (`site-public-djbclark/nixos/modules/cfengine-tendcf.nix`):
   binaries in the store, work directory `/var/lib/cfengine-tendcf`, an
   optional root `cf-execd --no-fork` unit. The module installs no policy
   and no `promises.cf`, so it sets no `exec_command`.
10. **`bin/projector.py` is the projection plus the N-series, and no
    more.** It does not validate the schema, does not refuse a goal file
    that is not canonical, has no version ceiling and keeps no state. Its
    `main()` reads a path and writes bytes to stdout.
11. **The canary goal files are fixture trust content.**
    `deploy/linux/canary/goal-file*.json` carry host key `ed25519:a1a1…`,
    advisor key `b2b2…`, agent digest `sha256:d4d4…`, policy-tree digest
    `sha256:c3c3…`, and `trust-policy.consent` `{tier: consented,
    local_yes_required: true}`. A validator that checks `device-trust`
    refuses all of them. pastebin needs a real goal file before any
    validator other than the projector runs there.
12. **Zero devices hold a device-side baseline.** Nothing device-side
    runs (map §12). pastebin's data was installed by hand, and no
    approved goal file is stored on any host.
13. **cf-execd starts a run on every schedule without checking whether
    the last one is still running.** `ScheduleRun` is followed by
    `LocalExecInFork` (`cf-execd.c:568-581`). Nothing checks for a run
    still in progress, so a wedged run has a new one started beside it
    every five minutes. `tendcf-install.sh`'s `exec_command` has no `-K`
    (line 137); `run-once` has it (line 180).
14. **With an empty `exec_command`, cf-execd runs its built-in failsafe
    command** `cf-agent -f failsafe.cf && cf-agent -Dfrom_cfexecd…`
    (`ConstructFailsafeCommand`, `cf-execd-runner.c:109-120`). That is
    today's NixOS shape (fact 9) once `execd.enable` is on. A non-interactive
    cf-agent whose policy fails `cf-promises` also writes and runs the
    built-in `failsafe.cf` (`generic_agent.c:205-245`).

## 1. Trigger and launch handoff

**(a) Question.** What starts `tendcf-validate` ahead of cf-agent, how
often does it run, and how is it guaranteed that cf-agent consumes the
projection that passed validation, and only that projection?

**(b) Options.**

1. **Wrapper as `exec_command`, every run, re-projecting from the stored
   baseline.** `tendcf-install.sh` writes
   `exec_command => "exec /opt/tendcf/libexec/tendcf-validate run -- $(sys.cf_agent) --no-augments -f $(sys.inputdir)/promises.cf"`.
   The leading `exec` makes the shell replace itself, whatever `/bin/sh`
   it is, so `pid_shell` is the wrapper (fact 5).

   `run` takes an exclusive `flock` on `<state>/lock`, **non-blocking**.
   A second `run` that finds the lock held exits at once and prints why.
   It writes no row and launches nothing, because fact 13 makes overlap
   a normal event and not a fault. `adopt` and `accept` wait for the lock
   with a bound, long enough for a normal run. When the bound expires
   they refuse with a lock-timeout error and change nothing (review
   finding 6). Once it holds the lock, `run` verifies the stored baseline
   generation (layout below) and promotes a pending approved proposal if
   one exists. It projects the current baseline, publishes the
   projection atomically, and starts cf-agent. Publication writes
   `data/.host_specific.json.tmp` (mode 0600, `fsync`), `rename(2)`s it
   over `data/host_specific.json`, and `fsync`s `data/`.

   The process protocol, from fact 5:

   - The wrapper forks cf-agent into a **group of its own**
     (`setpgid(pid, pid)` in both parent and child), so the child
     cf-execd picks is a group leader and its group kill reaches
     cf-agent's children.
   - The wrapper forwards SIGINT and SIGTERM to that group.
   - The wrapper enforces its **own deadline**, shorter than
     `agent_expireafter`. On expiry it terminates the group itself and
     records `complete: false`. cf-execd's kill path is then a backstop
     and never the mechanism.
   - It never has two children at once (fact 5's live assert).
   - When cf-agent dies by a signal or by the deadline, it skips every
     post-run step except the row.

   `exec_timeout` commands in their own groups survive any of this. That
   is CFEngine's residual and is unchanged by the wrapper.

   `run` holds the lock until cf-agent exits. `tendcf-install.sh run-once`
   becomes `tendcf-validate run -- cf-agent --no-augments -K -I -f …`.
   The projection is a pure function of the baseline (`project()` is
   pure, `bin/projector.py:251`), so re-deriving it costs one parse of
   one file of at most 5 MiB. Nothing retained between runs is trusted
   without re-checking.
2. **Once per approval, with a check in policy on every run.** `tendcf-validate
   accept` publishes the projection once, together with a sealed digest file
   `<state>/projection.sha256`. `exec_command` stays as it is. The
   generic bundle gains a first `classes:` promise,
   `hashmatch("$(sys.workdir)/data/host_specific.json", "sha256", <sealed digest>)`,
   and refuses to actuate when it does not hold. CFEngine still loads
   the vars before the check runs. The bundle refuses to act on them;
   it cannot refuse to load them.
3. **A separate scheduler replaces cf-execd.** A systemd timer (Linux,
   and NixOS through the module) or a launchd job (macOS) runs
   `tendcf-validate run -- cf-agent …`. cf-execd is disabled. The
   handoff is the same as option 1. CFEngine's own scheduling, splay,
   `outputs/` capture and `agent_expireafter` are replaced by unit
   configuration.
4. **A `commands:` promise inside the policy** runs `tendcf-validate`,
   which publishes for the next run. Listed because it is the obvious
   CFEngine idiom, and rejected: CFEngine loads the file before any
   bundle runs (map §12, `LoadCMDBData`). Every run would therefore
   apply the previous run's projection, and the retained file would
   still need an integrity check that CFEngine does not make (fact 1).

Common to all options, and recommended whichever is chosen: a launch
guard class. `run` passes `-D tendcf_validated` to cf-agent. The guard
sits in `promises.cf`, the entry file, and not in a bundle:

```
tendcf_validated:: bundlesequence => { "tendcf_interlocks", "tendcf_services" };
!tendcf_validated:: bundlesequence => { "tendcf_unvalidated" };
```

`tendcf_unvalidated` only reports. Guarding the bundles would not do:
`tendcf_interlocks` runs each interlock's `pre_action` command
(`policy/tendcf_services.cf:88-98`), so a guard inside `tendcf_services`
alone would still execute those commands on an unvalidated run (review
finding 2). Whether `body common control` accepts class-guarded
`bundlesequence` on the pinned fork is unverified (§12).

A cf-agent started any other way (a hand-run `cf-agent`, a future
`cf-runagent`, book ch. 35) then runs no tendcf bundle, instead of
acting on a stale file. **This guards against accidents and is not a
boundary.** The class can be supplied without the wrapper by:

- `-D` on the command line;
- a `classes` key in a `host_specific.json` that never passed the gate
  (`cmdb.c:739`; a validated projection cannot carry one, N-2);
- `def.json` or `def_preferred.json` in `inputs/`
  (`generic_agent.c:1036-1049`; the wrapper's `--no-augments` closes
  this for wrapped runs only);
- a persistent class in the state database (`generic_agent.c:1109`).

Every one of these needs root, and root is already inside the trust
boundary on these hosts. Before any bundle runs, an unvalidated
cf-agent can still do two things: its start-up housekeeping of the work
directory, and the built-in failsafe when the policy fails `cf-promises`
(fact 14). The guard reaches neither. The guard is a policy change, and
so a change to the policy-tree digest.

State layout (options 1-3). The state directory is
`$(sys.workdir)/state/tendcf/`, root 0700: under the Linux fork build
that is `/opt/tendcf/var/libntech/state/tendcf`, read from the binaries
as `tendcf-install.sh init_paths` does; on NixOS it is
`/var/lib/cfengine-tendcf/state/tendcf`. It holds:

- `gen/<sha256-of-goal>/goal.json`: the canonical bytes;
- `gen/<sha256-of-goal>/approval.json`: absent under the minimal build (§9);
- `current`: a symlink to one generation, replaced by `rename(2)`;
- `seq`: the `approval_seq` high-water;
- `rejects/`: persisted rejects (DC-2, DC-5);
- `nonce`: the pending device nonce;
- `lock`.

A promotion is: verify, write the new generation directory, `fsync`,
write `seq`, `fsync`, swap `current`, publish the projection, launch.

**(c) Consequences.**

- *Approved equals applied (map §9).* Under option 1, the bytes cf-agent loads are
  `project(current/goal.json)`, recomputed after `current` has been
  verified, under a lock that no promotion can take until cf-agent
  exits. Since CFEngine reads the file only at start-up, holding the lock
  for the whole run is more than strictly needed. Option 2 makes the
  guarantee one remove weaker: it rests on a policy-side `hashmatch`
  over vars that are already loaded, and on the sealed digest file not
  drifting from the baseline. Option 3 matches option 1. Option 4 does
  not provide the guarantee.
- *DC-2.* In options 1-3 the approval record is consumed once, at
  promotion, and `seq` advances then. A convergence run re-projects an
  already-approved baseline and never re-reads the approval as a new
  acceptance.
- *DC-11.* Neutral. Option 1 is the natural place to re-verify the
  policy-tree digest immediately before launch (item 3).
- *Fail closed.* A refused new proposal is not promoted. The reason is
  reported, and the host keeps converging on `current` (map §9.6). A
  `current` that fails verification (wrong digest for its generation
  name, schema-invalid, projection refused) means no cf-agent launch. The
  previous `host_specific.json` stays on disk but is inert, because of
  the guard class. The host freezes rather than converges (fact 3): a
  visible stall. cf-execd discards the exit status (fact 4), so the
  refusal has to reach the operator through `run`'s output, which
  cf-execd captures in `outputs/`, and through a report row. A timeout
  authorizes nothing: `run` never waits on an advisor (map §11).
- *Recovery.* A crash before the `seq` write leaves no state change. A
  crash after the `seq` write and before the swap consumes the approval
  without applying it: the host converges on the old baseline, and the
  proposal needs a fresh approval. That fails closed and costs one
  re-approval. A crash after the swap leaves the new baseline current,
  and the next `run` re-publishes the projection idempotently. A crash
  between publication and launch is harmless: the next run redoes both.
  A crash during or after cf-agent leaves nothing to undo or re-decide.
  The approval was consumed at promotion, before launch. The next run
  converges on the same `current`, which map §12 item 1 requires ("not
  treating each convergence run as a new acceptance"). Option 2 adds one
  more crash window, between publishing the projection and writing the
  sealed digest, which shows up as refusal runs until repaired.
- *Cross-item dependency.* Item 3 assigns several duties to `run`: the
  policy-tree check before launch, the convergence row, and starting the
  item 8 detector. Option 2 has no process that runs on every cycle, so
  under option 2 none of those has an owner. Options 1 and 3 both have
  one.

**(d) Recommendation: option 1, plus the launch guard class.** It is
the only option that keeps CFEngine's scheduler and also makes the
launcher and the validator the same process. The handoff is a function
call followed by `fork`/`exec`, not a file left lying between two
programs. Option 3 is equally sound. Take it instead if djbclark prefers
systemd/launchd scheduling to cf-execd, and on NixOS, where the module
already writes systemd units and installs no `promises.cf`.

**(e) Proof.** These tests run in the `tests/policy/run.sh` scratch
work directory with a real `cf-agent`/`cf-execd` (the
`TENDCF_TEST_SYSTEMD=1` VM job for the canary):

1. A `cf-execd --once` with the wrapper as `exec_command` repairs a
   stopped canary.
2. A tampered `current/goal.json` produces no cf-agent run: no new
   `outputs/` agent log, the canary is not repaired, the reason is
   printed and a row is written.
3. A refused proposal leaves `current` and the published bytes
   unchanged, and the canary still converges.
4. A hand-run `cf-agent -K -I` without `-D tendcf_validated` repairs
   nothing and runs no interlock `pre_action`.
5. An `accept` started during a `run` waits on the lock until cf-agent
   exits. A second `run` started during a `run` exits at once and
   launches nothing.
6. With an interlock that sleeps past the wrapper's deadline, the
   wrapper ends the run. No cf-agent and no child of it outside an
   `exec_timeout` group is left, and the row says `complete: false`.
   With the wrapper's deadline disabled and `agent_expireafter => "1"`,
   cf-execd's group kill gives the same result.
7. Crash windows: a unit test drives the promotion sequence through an
   injected filesystem layer that raises at each boundary listed under
   recovery, and asserts the state the next `run` sees. No fault
   injection goes into the shipped code.

## 2. What "validate" covers in the first build

**(a) Question.** Does the first `tendcf-validate` carry only the
structural checks or the whole map §9 validator, and what may it claim?

**(b) Options.**

1. **Structural only.** The checks are: `schema_version` dispatched
   first, with version above ceiling reported distinctly from
   schema-invalid (map §9.6); duplicate-key-free parse;
   refuse-never-normalize (the bytes equal `rfc8785.dumps` of the
   parse, map §9.2); JSON Schema validity against
   `goal-file.schema.json` v5; an unknown kind refuses the whole file;
   then `project()` and the N-series (`check_projection`). It keeps no
   state and has no notion of approval. This is `projector.py` with a
   front gate, in the `check` and `project` call shapes CI already uses.
2. **The full map §9 validator.** Everything in option 1, plus:
   - baseline integrity as a precondition (map §9.1);
   - the device-computed diff;
   - approval-record verification: every hash recomputed, the signature,
     `host` equal to this host's own key (see the device-identity row in
     item 3), the device nonce, `approval_seq` above
     the high-water, persisted rejects (DC-2);
   - the ceremony class derived from the baseline's structure and
     checked against the record (map §9.8, including the coverage
     transition table);
   - the migration empty-diff rule (map §9.4).

   It needs inputs that do not exist yet: an enrolled advisor key
   (Step 9), TUF metadata (Step 6 push), the R23 tree serialization, and
   an encoding for the nonce and the signature (the approval-record
   schema leaves both as "residue").
3. **Structural checks plus the item 1 state machine, adopted by a local
   operator, operator tier only.** Option 1's checks, the generation store,
   the lock, publication, the launch wrapper and refusal reporting. The
   only way to promote is `tendcf-validate adopt FILE`, run as root on
   the host. On these hosts root is the operator, the same trust
   boundary `tendcf-install.sh data` uses today. `adopt` **refuses** any
   goal file whose `device-trust.trust-policy.consent.local_yes_required`
   is `true`, because it cannot honour it. It records no approval record
   and claims none. Every `run` re-verifies the stored generation against
   its own name, the schema and the projection.

**(c) Consequences.**

- *Approved equals applied.* Option 1 gives none: there is no "approved"
  to be equal to. Option 2 gives the full map §9 property. Option 3 gives
  "applied equals the projection of the goal file root adopted, re-checked
  every run". That is honest for operator-tier hosts, where map §10's
  consent axis is "`operator`: no local yes", and it claims nothing about
  consent.
- *DC-2.* Option 1 is not applicable. Option 2 meets it in full. Option
  3 does not exercise it, and says so, by refusing every goal file that
  would need it.
- *DC-11.* None of the three can verify the policy-tree digest until R23
  specifies the tree bytes, or the agent digest until item 4 defines what
  it covers. Option 3 carries both fields without checking them, and
  must say so in its output.
- *Fail closed.* Option 1 is closed for a single invocation but leaves
  the launch handoff undefined. Options 2 and 3 are closed as in
  item 1.
- *Recovery.* Option 3's generation store is the store option 2 needs.
  Promoting from option 3 to option 2 adds `accept` and the approval
  checks, and does not redesign the state.
- *Fact 11 applies.* Options 2 and 3 both refuse the current canary goal
  files. pastebin first needs a goal file with its real host key and an
  honest `trust-policy`, presumably `{tier: operator,
  local_yes_required: false}` (an inference; djbclark's call), and
  then no `advisor-key` entry is required (the schema's `if/then`).

**(d) Recommendation: option 3 as the first build, and option 2 as the
completion of Step 6.** It is the smallest build that makes the next
operator host enforceable with a claim that is true. It reuses one state
design for both stages. It turns away the one case it cannot serve,
consented hosts, instead of serving it badly. Option 1 alone does not
answer item 1's handoff question, and so does not meet D45's "run before
cf-agent reads `host_specific.json`" in any checkable way.

**(e) Proof.**

1. CI runs the installed tree's own entry point
   (`python3 -I …/tendcf-validate check`) over `examples/` and
   `deploy/linux/canary/`, and expects the existing goldens
   byte-for-byte.
2. Every fixture under `examples/broken*`, `examples/broken-bytes`
   and `examples/broken-projection` is refused, each with its distinct
   reason class.
3. A copy of `goal-file.json` with `schema_version: 6` is refused as
   above ceiling, not as schema-invalid.
4. `adopt` refuses a goal file whose consent says `local_yes_required: true`.
5. A `run` after a byte has been flipped in `current/goal.json` refuses
   to launch.

## 3. The rest of the device-side gate on Linux and macOS

**(a) Question.** Which component owns each remaining device-side duty?
They are: TUF verification and high-water (map §9.11); the local-yes
exchange and device nonce (map §11, DC-2); the stored baseline (map §16
question 13); device-authored state (R24); the `--simulate-json` caller;
the policy-tree digest check; and the `device_convergence` row writer.

**(b) Options.**

1. **One program with subcommands, all root.** `tendcf-validate`
   would have these subcommands:
   - `run`: item 1;
   - `adopt`: item 2, option 3;
   - `propose GOAL`: issues the nonce, computes the device diff, renders
     the briefing, optionally runs `cf-agent --simulate-json` in a
     scratch work directory;
   - `accept GOAL RECORD`: verifies TUF metadata and the approval
     record, then promotes;
   - `status`.

   The R24 state lives in its state directory. The network fetch, if
   any, is in-process.
2. **One program, with only the network outside it.** The same
   subcommands, except that release bytes arrive through a spool:
   `scp` by the pusher at Step 6 ("push-only", map §13), and an
   unprivileged fetcher at Step 8 (pull). `accept` treats the spool as
   untrusted input and verifies the TUF signatures itself, as root,
   before parsing anything else. This keeps
   `tendcf-install.sh`'s rule that "nothing a non-root user can write is
   read by root" (lines 10-11) in its only safe form: root reads such
   bytes only after verifying them.
3. **Several commands.** `tendcf-validate` stays a gate plus a projector
   and nothing else. A sibling `tendcf-consent` owns the nonce, the
   briefing, `--simulate-json` and the advisor exchange, and
   `tendcf-report` writes rows. Each command is a separate artifact with
   its own digest, and the trust boundary is drawn between them.

The individual assignments, under options 1 and 2:

| Duty | Owner | When |
| --- | --- | --- |
| Stored baseline (map §16 Q13) | `gen/`+`current` in the root 0700 state directory, re-verified every `run`. Under option 2 of item 2 the stored approval record's signature is re-verified too, so tampering needs an advisor-key forgery and not only root. | first build (without the signature) |
| R24 state: nonce, `seq`, rejects, TUF root and high-water | same state directory, its own files; never a copy of any `device-trust` content (R24's P-8 condition) | Step 6 |
| TUF verification and high-water | `accept` | Step 6 |
| Local-yes exchange | `propose` (nonce, briefing) and `accept` (record); a timeout means no `accept`, so nothing is promoted (map §11) | Step 9 |
| `--simulate-json` | `propose` only, as the human-facing confirmation map §9.1 allows; never `run`, never the gate | Step 9 |
| Device identity key | The goal file's `host` and the approval record's `host` are a device public key (`ed25519:` plus hex; "host identity is the key, not the hostname", `goal-file.schema.json`). No host has one: `cf-key` makes CFEngine's own RSA pair (`cf-key-functions.c:322`), which is a different key. Generating it, storing its private half and the enrollment ceremony belong with DC-1 and R24 (review finding 11, amended: the identity is a key, never a hostname) | before the first `adopt` that checks `host`; Step 6 at the latest |
| Policy-tree digest (change-process.md §3) | `run`, immediately before launch. The digest must cover **every file cf-agent reads from `inputs/`**: `promises.cf` (which `tendcf-install.sh` writes, lines 125-141, and which holds `exec_command`) as well as `tendcf/`. Any other file there refuses the launch, which covers `def.json`, `def_preferred.json` and a failsafe-written `failsafe.cf`. Today's tree tarball (change-process.md §3) holds only the bundles, so either R23's serialization covers the whole `inputs/` tree or the installer renders `promises.cf` from the tree. The wrapper's `--no-augments` is a second line (review finding 4) | once R23 is specified |
| `device_convergence` row | `run`, after cf-agent exits. `schema_ceiling` is the validator's own constant. `complete` needs the policy to say whether an interlock blocked (the row's own definition), so the bundle writes a one-run outcome file that `run` reads. Two gaps (review findings 7 and 8, amended). First, `release` and `converged_release` are required `release_stamp`s, "the signed release that produced this row", and before Step 6 there is no signed release: the minimal build either writes no rows or names the adopted goal file in a field defined as a signed release (picklist 12). Second, one row per run is about 288 rows a day on cf-execd's 5-minute default; JSONL retention is map §8's, and undecided | first build, subject to picklist 12 |

**(c) Consequences.**

- *Approved equals applied.* Options 1 and 2 put every check the
  guarantee depends on into the one process that launches cf-agent.
  Option 3 spreads them across processes, and each handoff needs its own
  integrity story: item 1's problem, repeated.
- *DC-2 and DC-11.* The same in all three. Option 3 adds a digest per
  command to the agent entry (item 4).
- *Fail closed.* Option 1 runs network-facing parsing as root. Option 2
  runs as root only the parser of signed metadata, and does so before
  trusting anything.
- *Recovery.* One state directory with one lock (options 1 and 2) has
  one recovery procedure. Option 3 needs a lock protocol across commands.
- *The two-phase rule (map §9.6)* reads `schema_ceiling` from these rows,
  so without the `run` row writer the rule has no per-host input on
  Linux and macOS.

**(d) Recommendation: option 2.** One artifact, one digest, one lock and
one state store, and network bytes never parsed as root before
verification. The duties come in by build step: the baseline store and
the row writer in the first build; TUF and `accept` at Step 6; the
local-yes exchange and `--simulate-json` at Step 9. The policy-tree check
comes in when R23 lands. Splitting into option 3 buys a privilege
boundary that is not needed while everything runs as root anyway.

**(e) Proof.** Each test enters with its duty:

1. A replayed record (same `approval_seq`) is refused.
2. A record for another `host` is refused.
3. A TUF snapshot older than the high-water is refused.
4. A tampered file under `inputs/tendcf/` blocks launch once R23 exists.
5. After a run blocked by an interlock, the `device_convergence` row
   validates against `report-row.schema.json` with `complete: false`.
6. A spool file written by an unprivileged user with an invalid
   signature is rejected before any JSON schema validation runs. The
   test asserts the order through the refusal reason.

## 4. The `device-trust` `agent` entry

**(a) Question.** On Linux and macOS, does the id `tendcf-agent` change,
which costs a schema bump, and what bytes does its `sha256` bind?

**Stale fact corrected.** Map §12 item 4 says "the schema is at v4 and
v5 is in flight; an id change decided before v5 lands rides that bump".
v5 has landed (`goal-file.schema.json` `schema_version` const 5; tendcf
PRs #34, #35, #37, #39 and nix2cf #5). An id change now costs v6, and
nix2cf must render v5 for every host until it reports a ceiling of 6
(map §9.6). The "baseline ceremony per device" it also names costs
**nothing today**: no device holds a baseline (fact 12). It starts to
cost something with the first `adopt` on any host. If the id changes at
all, the cheapest moment is before the first build is installed.

**(b) Options.**

1. **Keep the id, and define the bytes as the validator tree.** `sha256`
   is the digest of the installed `tendcf-validate` tree: entry script,
   modules, vendored dependencies (item 5). It is serialized by the same
   rule R23 must define for the policy tree, so one tree-serialization
   rule serves both digests. The interpreter and the standard library are
   declared a trusted host runtime outside the artifact (item 6), in the
   same class as the CFEngine binaries in `/opt/tendcf`. Those are not
   digest-bound by any goal-file entry either (an observation: no
   `device-trust` kind names the CFEngine build).
2. **Keep the id, and bind a self-contained bundle.** Same as option 1,
   but the tree includes the interpreter: a relocatable CPython (for
   example python-build-standalone) under `/opt/tendcf` on Linux and
   macOS. On NixOS it is the derivation's closure, and the digest is the
   store path's NAR hash. Nothing is left as host runtime except libc and
   the kernel.
3. **Rename the id in v6** to a platform-neutral name (for example
   `validator`, with the platform implied by `supervisor`), with the
   bytes as in option 1 or 2. This is a schema bump plus multi-version
   render in nix2cf, and fixture churn in both repos, bought for a
   clearer name.

**(c) Consequences.**

- *DC-11.* Option 2 meets it for everything the validator executes.
  Option 1 meets it for the code tendcf ships, and puts the interpreter
  outside the accepted artifact. The map already says that choice is
  djbclark's to define and that "pinning a version alone does not satisfy
  DC-11". Option 3 is neutral on DC-11.
- *The two-phase rule.* All three keep the agent entry as the hunk a
  validator update rides on.
- *Approved equals applied, fail closed.* A `run` that checks its own
  tree digest against `current`'s agent entry refuses when the installed
  validator is not the approved one. That is the gate on the gate. It
  can enter only after the serialization rule exists.
- *Recovery.* A refused self-check is a stall that needs an out-of-band
  reinstall of the approved tree. With option 2, the out-of-band step
  also brings the interpreter back.

**(d) Recommendation: option 1 on Linux, option 2 on macOS** (item 6),
**and no rename.** Debian's `python3` is trusted the way `/usr/bin` and
systemd already are on a root-run host. macOS has no system interpreter
that is root-owned and new enough (item 6), so the bundle has to carry
one there. A rename buys only a name: if djbclark wants one, rule it
before the first `adopt`, and not afterwards.

**(e) Proof.**

1. Two clean CI checkouts serialize the installed tree to identical
   digests.
2. A `run` with one byte of the installed tree changed refuses to
   launch, once the self-check is enabled.
3. On macOS, a test fails the install when any component of the
   interpreter's resolved path (`realpath` of every link) is writable by
   a non-root user. The layout measured below must fail it.

## 5. The `rfc8785` dependency

**(a) Question.** How does the privileged command get its JCS
implementation without `uv` resolving or downloading anything at run time?

Facts: PyPI `rfc8785` 0.1.4 (Trail of Bits, Apache-2.0) describes itself as
"a pure-Python, no-dependency implementation" and declares
`requires_python >=3.8` (PyPI JSON, read 2026-11-02). The goal file has no
floats (map §9.2), so the hardest part of JCS, number serialization, only
ever sees integers here. `projector.py` imports it once, for
`rfc8785.dumps` (line 319). The `>=3.11` floor is declared by
`projector.py` itself (line 3), not by `rfc8785`.

**(b) Options.**

1. **Vendor it.** Copy the `rfc8785` package source into the
   validator tree at a pinned release, with a recorded upstream digest
   and its licence. It is covered by the item 4 digest. The entry
   point runs under `python3 -I` and puts its own tree on `sys.path`
   explicitly (`-I` keeps the script directory and user site-packages
   off it).
2. **Use the OS package.** Debian's or nixpkgs' `rfc8785`, if packaged
   (not verified here; see §12). It is outside the item 4 digest and
   updates with the distribution.
3. **Implement JCS in the command**, restricted to what the goal file
   allows: no floats, so integer formatting, UTF-16 code-unit key
   ordering and JCS string escaping. Keep `rfc8785` as a CI-only oracle,
   compared byte-for-byte over the corpus.

**(c) Consequences.**

- *DC-11.* Option 1 brings the dependency under the accepted digest.
  Option 2 leaves it outside, so it becomes part of item 4's "trusted host
  runtime" at a version tendcf does not choose. Option 3 has no
  dependency.
- *One implementation (D45).* Options 1 and 2 keep the code CI runs
  identical to the code the device runs, provided CI runs the installed
  tree and not `uv run --script`. Option 3 adds a second JCS, held to the
  first only by a CI oracle, which is the kind of drift D45 exists to
  avoid.
- *Fail closed.* All three are equivalent once installed.

**(d) Recommendation: option 1.** It is a small pure-Python package with
no dependencies, so vendoring costs a directory and a digest, and it keeps
D45's "one implementation" literal. CI's golden gate then runs exactly the
installed tree (`python3 -I`), instead of `bin/projector.py` under
`uv`. The repo's `uv run --script` header becomes a development
convenience only.

**(e) Proof.**

1. On a CI host with no network and an empty user site, the installed
   tree passes `check` over the corpus.
2. A planted `rfc8785.py` in the working directory and in user
   site-packages is not imported. The test asserts
   `rfc8785.__file__` lies under the install prefix.
3. `uv` is absent from the device image and the run succeeds.

## 6. Interpreter, prefix, and execution identity

**(a) Question.** Which `python3` runs on each platform, where is the
command installed, and under which identity and privilege boundary do
validation and publication run?

Measured on the review Mac (2026-11-02):

- `/usr/bin/python3 --version` reports 3.9.6. The Command Line Tools
  interpreter (`/Library/Developer/CommandLineTools/usr/bin/python3`,
  root:wheel) also reports 3.9.6.
- `xcode-select -p` is `/Applications/Xcode.app/Contents/Developer`.
- `/Applications` is `root:admin drwxrwxr-x`, writable by the admin
  group. `/Applications/Xcode.app` is owned by `djbclark:staff`.

So on this machine the `/usr/bin/python3` shim resolves into a tree a
non-root user owns. A root-run validator that starts it would execute
code a user can replace, and the interpreter is below the declared
`>=3.11` in every case.

**(b) Options.**

1. **Host interpreter everywhere.** Debian/Ubuntu `/usr/bin/python3`,
   declared as an install dependency, with the version floor checked by
   `tendcf-install.sh` and again by `run`. NixOS gets it through the
   derivation. On macOS, the CLT interpreter is used by absolute path,
   never the `/usr/bin` shim.
2. **Bundled interpreter everywhere** (item 4, option 2), under
   `/opt/tendcf/libexec/tendcf-validate/` on Linux and macOS, and in
   the store on NixOS.
3. **Host interpreter on Linux and NixOS, bundled on macOS.**

Prefix: `/opt/tendcf` is already the root-owned CFEngine tree on Linux
(`tendcf-install.sh:30`). Putting the validator under
`/opt/tendcf/libexec/tendcf-validate/` puts it inside that boundary and
`check_tree`'s ownership pass. On NixOS the prefix is the store path.

Identity: in every option, one root process validates, publishes and
launches. It must be root, because the destination is the root 0700
`data/` (fact 8) and cf-agent runs as root. A split, with validation
unprivileged and publication root, only moves the parser out of root,
and the publisher would have to re-verify everything (§3). Revisit
that at Step 8, when untrusted network bytes first arrive.

**(c) Consequences.**

- *DC-11.* Option 1 on macOS fails both the version floor and, through
  the shim, the ownership rule, as measured above. The CLT path is
  root-owned, but Apple's software update changes it outside any
  artifact tendcf approved. Option 2 binds the most. Option 3 binds what
  macOS cannot otherwise make trustworthy.
- *Fail closed.* `run` refuses when the interpreter is below the floor,
  or when its resolved path chain is writable by a non-root user.
- *Recovery.* With a host interpreter, a distribution upgrade can move
  `python3` across the floor. `run` refuses it (a stall) until the tree
  is updated.
- `LD_LIBRARY_PATH`: the cf-execd unit exports
  `LD_LIBRARY_PATH=/opt/tendcf/lib` (`tendcf-install.sh:194`). The
  interpreter inherits it. `exec_command` should start the interpreter
  with a clean environment and set `LD_LIBRARY_PATH` only for the
  cf-agent child. This is an inference: nothing measured shows a
  library clash today.

**(d) Recommendation: option 3, prefix `/opt/tendcf/libexec/tendcf-validate/`
on Linux and macOS, and one root process.** The macOS measurement
decides it: neither system interpreter is both new enough and a
root-owned path. On Linux the distribution's `python3` is no less trusted
than the rest of the root-run host.

**(e) Proof.**

1. An install-time test on each CI image (ubuntu-24.04, 26.04, arm,
   `debian:13`) asserts that the interpreter meets the floor and that its
   `realpath` chain is root-owned and not group- or other-writable.
2. The same assertion fails against the macOS layout measured above.
3. `debian:13` without `python3` installed makes `tendcf-install.sh`
   refuse with a named dependency.

## 7. The SQLite index on Linux and macOS (map §8, D18)

**(a) Question.** Who owns the rebuildable SQLite index over the JSONL
capture on hosts with no daemon?

**(b) Options.**

1. **Not built on these platforms** until a consumer needs one. JSONL is
   the record, queried with `jq`.
2. **Built on demand** by a `tendcf-validate report --index` subcommand,
   rebuilding from the JSONL into a cache file nothing else trusts.
3. **Maintained by `run`**, appending to the index after each row.

**(c) Consequences.** None of the options touches map §9's guarantee, DC-2 or
DC-11: map §8 already says nothing depends on the index. Option 3 puts a
SQLite writer in the privileged launch path, so a locked or corrupt
index could stall a run. That would add a failure mode to the gate for
the sake of a convenience. Option 2 is safe because the index is
disposable.

**(d) Recommendation: option 1, with option 2 as the upgrade path when a
consumer appears.** The JSONL writer is the real gap (map §8: "nothing
writes report rows"), and item 3 assigns the `device_convergence` row
to `run`.

**(e) Proof.** For option 1: none needed beyond the row schema test in
item 3. For option 2, when built: delete the index, rebuild it, and
compare query results with `jq` over the JSONL.

## 8. The v5 detector

**(a) Question.** Does the unit-namespace detector stay in the CFEngine
policy bundle (R4 of
[`schema-v5-dpkg-reconciliation-2026-11-02.md`](schema-v5-dpkg-reconciliation-2026-11-02.md)),
or does another command take it over?

A fact the open item does not state: **the detector's input does not
project.** `unit-writer` and `unit-package` are "detector data and do
not project" (v5 reconciliation §2.1, and item 7 of its §7;
`projector.py` P-1, lines 27-29). A bundle-resident detector therefore
cannot reach the claims through `host_specific.json`. Some other path
must deliver them. Also: `bin/unit_classifier.py` already implements the
detector contract as a read-only Python prototype. It was proven on CI
fixtures and in an unprivileged read of pastebin (v5 reconciliation
§3.6-§3.7), and its docstring says "no root needed, nothing is written".

**(b) Options.**

1. **Native policy, as ruled (R4).** The classifier is rewritten as
   CFEngine promises (`systemctl show`, `dpkg-query -S`, link chains).
   The claims are delivered either by a P-1 change, so that the claims
   project (a projector-reconciliation change, and a second read path
   into `data:` for non-actuated data), or by a separate claims file the
   validator writes for the bundle to read with `readjson()`. Either
   way this is a second implementation of a contract that already has a
   proven one.
2. **A sibling command started by `run`.** `unit_classifier.py` is
   promoted to a read-only `tendcf-detect`. `run` starts it after
   cf-agent exits, as an unprivileged user, and feeds it the claims
   extracted from the verified `current` goal file. `run` writes the
   resulting report row. This reopens R4's placement.
3. **The bundle runs the Python classifier.** A `commands:` promise with
   `contain => { exec_owner => "nobody" }` runs the classifier and
   reads its JSON. The validator writes the claims file it needs. This
   keeps R4's "lives in the policy bundle" as the scheduling owner, with
   one implementation. It still needs the claims file from option 1.

**(c) Consequences.** The detector is threat-modelled for accidents only
(R3b) and is report-only, so none of the options touches map §9's
guarantee, DC-2 or fail-closed behaviour. DC-11: options 2 and 3 run
Python code that must sit inside the item 4 digest, as part of the same
tree. Option 1 puts it under the policy-tree digest. On recovery: a
detector failure must leave the scan `incomplete` and never block a
run. v5 K12 already rules that evidence the scan cannot establish makes
it `incomplete`; a crash of the whole detector is this proposal's
extension of that rule. This holds in all three options, provided
option 2 runs after cf-agent and ignores the detector's exit status for
launch purposes.

**(d) Recommendation: option 2, and so an amendment of R4.** That is
djbclark's ruling to make. The claims live in the goal file, which only
the validator reads. The proven implementation is Python. D45's
one-implementation argument applies to it unchanged. Keeping the detector
out of `tendcf-validate` itself keeps the gate free of host-state
interpretation. If R4 stands, option 3 is the cheaper way to honour it.

**(e) Proof.**

1. `tests/unit_classifier/` passes unchanged against the promoted command.
2. A `run` on the systemd VM job emits a schema-valid
   `extra_scan` row with claims taken from `current`.
3. A detector that crashes still leaves the cf-agent run and its
   `device_convergence` row intact.

## 9. Minimal first build

Under the recommendations above (item 1 option 1, item 2 option 3,
item 3 option 2's first-build duties, item 4 option 1 or 2, item 5 option
1, item 6 option 3), the smallest `tendcf-validate` that is honest is:

1. **Tree.** `/opt/tendcf/libexec/tendcf-validate/` (root-owned, inside
   `check_tree`), containing:
   - `projector.py`'s module, unchanged in what it projects;
   - a front gate: version dispatch, duplicate-key parse, canonical-bytes
     refusal, JSON Schema v5 validity, unknown-kind refusal;
   - vendored `rfc8785`;
   - an entry point run as `python3 -I`.

   On macOS the tree adds a bundled interpreter. Validating JSON Schema
   needs a validator library (an implementation detail this proposal
   does not choose): vendor it like `rfc8785` and bring it under the
   same digest, or check the v5 schema's constraints in code held to
   `bin/schema_lint.py`'s verdicts on the corpus.
2. **Subcommands.** `check` and `project` are the CI call site. `adopt
   FILE` runs as root and refuses `local_yes_required: true`. `run --
   CF-AGENT-ARGV` follows item 1, and writes one `device_convergence`
   JSONL row per run. `status` reports state.
3. **State.** The item 1 generation store, lock and atomic publication.
   `seq`, `rejects/` and `nonce` are not yet used.
4. **Install changes** (the build's PR, not this one):
   - `tendcf-install.sh` installs the tree, writes the wrapper
     `exec_command`, and routes `run-once` through `run`;
   - `data` becomes `adopt`;
   - `promises.cf` gains the `tendcf_validated` guard on
     `bundlesequence`, and the generic bundle gains the one-run outcome
     file for `complete`;
   - pastebin gets a real goal file (fact 11).

**It does not yet guarantee:**

1. *Consent.* No approval record, nonce, `approval_seq` or advisor. No
   consented host is admitted. "Approved" means "adopted by root on the
   host".
2. *Release authenticity.* No TUF verification or high-water. The goal
   file is whatever root adopts.
3. *DC-11 for the policy tree and the validator.* Both digests are
   carried, not checked, until R23 and item 4's serialization exist. The
   installed policy is whatever `tendcf-install.sh place_policy` copied.
4. *Baseline protection beyond root ownership* (map §16 Q13). An attacker
   with root can rewrite the generation and its name together.
5. *The device-computed diff, ceremony class and coverage-transition
   checks* (map §9.1, §9.4, §9.8). With no approval record there is
   nothing to check them against.
6. *Effects* (map §9.10). Unchanged in every option.
7. *Host binding.* No host has a device identity key yet (item 3), so
   `adopt` cannot check that the goal file's `host` is this host.
8. *Interlocks against a loader that drops their container* (fact 2).
   No option in items 1-8 closes this. §13 does, once djbclark rules on
   it.

It does guarantee three things:

- cf-agent, when launched through `run`, loads exactly
  `project(current/goal.json)`. That is the bytes; which of them the
  loader then installs is fact 2's caveat;
- `current` passed the structural checks, and passes them again on
  every run;
- a refusal by `tendcf-validate` is visible and never fails open. This
  covers the validator's own refusals, not the loader's silent skips
  (§13).

## 10. Operator picklist

1. Trigger: (1) wrapper `exec_command`, every run, re-project from the
   baseline [recommended], plus the launch guard class on
   `bundlesequence` in `promises.cf`, an accident guard only
   [recommended];
   (2) once per approval, with a policy `hashmatch` check; (3) a
   systemd/launchd timer replaces cf-execd; (4) a `commands:` promise
   (rejected).
2. First-build scope: (1) structural checks only; (2) the full map §9
   validator; (3) structural checks + state machine + root `adopt`,
   operator tier only [recommended; option 2 completes Step 6].
3. The rest of the gate: (1) one program, root, network in-process;
   (2) one program, network outside, spool verified as root
   [recommended]; (3) several commands.
4. The agent entry: (1) keep the id, digest the validator tree, host
   interpreter trusted [recommended on Linux]; (2) keep the id, digest
   a bundle that includes the interpreter [recommended on macOS];
   (3) rename the id in v6 (only before the first `adopt`).
5. `rfc8785`: (1) vendor [recommended]; (2) OS package; (3) implement
   JCS in the command.
6. Interpreter and prefix: (1) host everywhere; (2) bundled everywhere;
   (3) host on Linux/NixOS, bundled on macOS, under
   `/opt/tendcf/libexec/tendcf-validate/`, one root process
   [recommended].
7. SQLite index: (1) not built [recommended]; (2) on demand;
   (3) maintained by `run`.
8. Detector: (1) native policy (R4 as ruled); (2) a sibling command
   started by `run`, amending R4 [recommended]; (3) the bundle runs the
   Python classifier.
9. pastebin's goal file (fact 11): rule its real `trust-policy` tier
   before any validator other than the projector runs there.
10. **Interlock fail-open (§13; live design, pastebin included):**
    (1) projector-synthesized interlock reference (breaks R21 and P-2);
    (2) author-declared `interlocked` field, schema v6; (3) the policy
    checks the loaded keys against the file with `readjson` and
    `isvariable` [recommended]; (4) the wrapper checks
    `cf-promises --show-vars` before launch; (5) an all-or-nothing CMDB
    loader in the fork.
11. How report rows leave a Linux or macOS device (review finding 9;
    map §8, linux-targets.md §4 item 3): (1) the pusher collects the
    JSONL over SSH at each push, fitting Step 6's push-only and needing
    no device credentials [recommended]; (2) the device sends rows to
    an operator endpoint, which needs credentials on the device; (3)
    nothing leaves the device before Step 8, and rows are read on demand.
12. The `release` column before Step 6 (item 3 table): (1) write no
    `device_convergence` rows until signed releases exist; (2) write
    rows whose `release` names the adopted goal file, documented as "not
    a signed release", which strains the column's definition;
    (3) amend `report-row.schema.json` to allow an explicit unsigned
    marker (a schema change). No recommendation: (1) loses the
    first build's only report, and (2) and (3) bend the column.

## 11. Stale facts corrected

This proposal records these corrections. It does not edit the documents
that hold the stale text, per its brief.

1. **Map §12 item 4**, "the schema is at v4 and v5 is in flight": v5 has
   landed (`schema_version` const 5). An id change costs v6. Its
   per-device baseline-ceremony cost is zero today, because no device
   holds a baseline (item 4).
2. **Map §9.8 (last bullet), map §16 question 14, and change-process.md
   §3** ("whose digest the goal file will carry once map §9.8's
   obligation is discharged. Until then the digest is recorded in
   `targets.json`"): the goal-file schema has required
   `device-trust.entries.policy-tree.tree.sha256` since the schema family
   landed (`9fdf437`, 2026-08-15; `policy_tree_map`, "R8 paid at the
   schema layer"). What is unpaid is R23 (the tree's byte sequence) and
   a device-side verifier, not the schema binding.
3. **`bin/projector.py:142-144`** (E-5: an expansion sequence "fails the
   ENTIRE CMDB load"): true of stock 3.27.1, which the comment cites.
   On the pinned fork it is false: `ReadCMDBVars` skips only the
   offending entry (fact 2). The N-3 refusal matters more there, not
   less, because a partial load can drop the interlocks alone.
4. **`bin/schema_lint.py:802-803`** ("the projection is hash-bound on the
   approval record"): it is not. The `H(projected_augments)` extension
   was dropped
   ([`goal-file-schema-reconciliation-2026-08-15.md`](goal-file-schema-reconciliation-2026-08-15.md),
   §11), and `approval-record.schema.json` has no
   such member. The projection is bound only through the goal file it is
   a function of.
5. **Map §12 item 1** ("deleting or withholding the projection is not a
   demonstrated fail-closed launch protocol") is right, and fact 2
   strengthens it: on the pinned fork, a *malformed* projection is not
   even all-or-nothing.
6. **`deploy/linux/tendcf-install.sh` `put_data`** is not atomic against
   a concurrent cf-agent (fact 8). This matters once a scheduler runs,
   which stage B enables.
7. **This proposal's own first text** (commit `a7b7c31`, fact 5 and item
   1 option 1) had the wrapper call `setpgid(0,0)` and said no cf-agent
   could survive the timeout kill. In the shell-`exec`s case that left
   cf-agent outside any group cf-execd signals. Corrected in fact 5 and
   item 1 (review finding 1).

## 12. Not verified

1. Debian's standard task shipping `python3`, and the versions on
   Debian 13 and Ubuntu 24.04/26.04: carried from map §12 item 6; this
   slice ran no remote host.
2. Whether `rfc8785` is packaged in Debian or nixpkgs.
3. Whether `projector.py` needs Python 3.11, or merely declares it.
4. What a CLT-only Mac (no Xcode.app) resolves `/usr/bin/python3` to.
   Only this Mac's Xcode-selected layout was measured.
5. Every option above is unbuilt. No test in §1-§8 or §13 has been run;
   each is a specification of the proof, not a result.
6. The cf-execd timeout behaviour (fact 5) and the process protocol in
   item 1 were read in the source, not exercised. So was whether the
   hosts' `/bin/sh` `exec`s a single simple command. The `exec` prefix
   makes item 1 independent of that.
7. Whether `body common control` accepts a class-guarded
   `bundlesequence` on the pinned fork (item 1's guard, §13 option 3).
8. Whether `readjson` plus `isvariable("data:variables.<key>")` compose
   as §13 option 3 needs.
9. Whether `cf-promises --show-vars` lists CMDB containers in a form
   §13 option 4 can parse reliably.

## 13. The interlock fail-open: for the operator

**This is a fail-open in the live design, independent of
`tendcf-validate`, and it applies to pastebin today.** The canary
projection that `tendcf-install.sh install --data` puts on pastebin
(deploy/linux/README.md) carries both containers: its `vars` keys are
`tendcf_interlock` and `tendcf_service`, checked 2026-11-02. Any skip of
the first leaves the second ungated. No skip is known to happen with the
current bytes, which pass the N-series. It is flagged for djbclark, not
decided here.

**(a) Question.** When the CMDB loader installs `tendcf_service` but
not `tendcf_interlock` (fact 2), how does the policy refuse, instead of
running every service ungated?

The reviewer's remedy, checked: Argon (review finding 3) proposes that
the projector add `"interlock_id"` to each `tendcf_service` entry,
computed from whether that service's `bundle` tag has an interlock, and
that the policy then gate services *positively*. The projector cannot do
that without breaking its own contract:

- The join reads entry *values* (the services' and the interlocks'
  `bundle` strings) to decide output *structure*. R21 and map §9 name
  that as "the interpreter returning", and `projector.py`'s docstring
  calls it R21's tripwire.
- It writes a key into a service body that the goal file does not hold.
  P-2 and P-6.5 copy the body verbatim, and P-2's container prefix is
  the only token the projector synthesizes.

So option 1 below is the reviewer's remedy, recorded and not
recommended. The remedy should depend on nothing about *why* the
container was dropped. Today's known cause (an unexpanded `$(`) is
already refused by N-3, but the loader can refuse for reasons the
projector does not model: `AddCMDBVariable`'s own checks, or a later
CFEngine.

**(b) Options.**

1. **Projector-synthesized per-service interlock reference** (Argon).
   This touches `bin/projector.py` (P-1, P-2 and the goldens), the
   Kotlin port (R22) and `policy/tendcf_services.cf`. It violates R21
   and P-2 as above. Not recommended.
2. **Author-declared binding in the goal file (schema v6).** A service
   entry gains a required boolean, for example `interlocked`, resolved
   by nix2cf. A lint checks it against the interlock entries'
   `bundle` tags. It projects verbatim, so the projector does not
   change. The policy refuses a service with `interlocked: true` unless
   an interlock class for its bundle was evaluated. The cost is a v6
   bump, multi-version render in nix2cf, and one fact spelled twice,
   needing a consistency lint.
3. **The policy checks the loader against the file.** Projector and
   schema stay unchanged. A `bundle common` in `tendcf_services.cf`
   reads the projection itself:
   `readjson("$(sys.workdir)/data/host_specific.json", 5242880)`. For
   each key under `vars`, it defines a missing class when
   `isvariable("data:variables.<key>")` fails. `promises.cf` selects a
   refusing `bundlesequence` if any missing class is set, or if the file
   cannot be read. The fork skips per top-level `vars` key, and a
   container is one key, so the key-set comparison sees every skip
   whatever its cause. Cost: a second parse of a file of at most 5 MiB,
   and a policy change, so a change to the policy-tree digest. Untested
   on the pinned fork (§12).
4. **The wrapper checks the loader before launch.** Projector, schema
   and policy stay unchanged. After publication, `run` runs
   `cf-promises --show-vars` against the same work directory. It refuses
   the launch unless every `vars` key in the published bytes is
   reported installed under `data:`. Same binary, same bytes, same
   loader, so it sees the same skips. Cost: one extra `cf-promises` run
   per launch, and parsing `--show-vars` output, which is not a stable
   interface. Wrapped runs only, which the launch guard makes the only
   runs that act.
5. **Make the loader all-or-nothing in the fork.** Change `ReadCMDBVars`
   so that one skipped entry fails the whole `vars` section, with no
   services installed and the host frozen (fact 3). This is the
   opposite of overlay patch `8f0076b81` (B-5b in
   [`upstream-register.md`](upstream-register.md)), which tendcf
   introduced to narrow the blast radius, and it diverges from what was
   proposed upstream. Projector and policy stay unchanged.

**(c) Consequences.**

- *Approved equals applied.* Options 2-5 each make "the approved
  interlocks are in force, or nothing actuates" hold. Option 1 makes it
  hold too, at the cost of the projector's discipline.
- *DC-2 and DC-11.* None. Options 1-3 change the policy, so the
  policy-tree digest changes. Option 4 changes the validator tree, so
  the agent digest changes (item 4).
- *Fail closed.* Options 3 and 5 hold for any launch path, wrapped or
  not. Option 4 holds for wrapped launches. Option 2 holds only for
  services the author marked, so a missing mark is a silent hole that
  only the lint can catch.
- *Recovery.* All of them freeze the host (fact 3) until the cause is
  fixed. The refusal must be reported, which in option 3 the policy's
  report does and in option 4 `run`'s output does.

**(d) Recommendation: option 3.** It needs no projector, schema or fork
change. It covers every launch path. It keys on the loader's actual
behaviour and not on a model of it. Option 4 is the fallback if
`readjson` plus `isvariable` turn out not to compose on the pinned fork.
Rule on this before any further host is enforced with interlocks. It
also bears on pastebin, which already is (see above).

**(e) Proof.** A policy test with a real `cf-agent` (`tests/policy/run.sh`):

1. A projection whose `tendcf_interlock` container carries a `$(x)`
   value, written past the projector so that the fork skips the
   container, actuates no service, and the refusal is reported.
2. The same projection with the container intact actuates normally.
3. A projection with no interlocks at all actuates normally.

Run test 1 against the current policy first: it must actuate the
service. That reproduces the fail-open before the fix.

**Implemented 2026-11-06: option 3, per djbclark's ruling Q10 (2026-11-02).**
`bundle common tendcf_cmdb` in `policy/tendcf_services.cf` reads
`$(sys.workdir)/data/host_specific.json` with `readjson` (5 MiB cap) and
compares it with the data the loader installed. For every `vars` key it
requires `data:variables.<key>` to exist and the key's entry ids to equal
the loaded container's indices (a half-loaded container is caught). It also
refuses a loaded `data:variables.*` that is not a `vars` key of the file, a
file that exists but cannot be parsed, and loaded data with no file. A missing
file with nothing loaded is the normal empty case and says nothing. On any
mismatch it defines the one class `tendcf_cmdb_refused`, and
`tendcf_interlocks` reports what differs once. Both bundles then see empty
`interlock_ids` and `service_ids`: no pre_action, no service, no tombstone.
It is a `bundle common`, so cf-agent evaluates it to completion before the
first agent bundle whatever `bundlesequence` says, which is what makes the
class final before any gate is read. `bundlesequence` guard classes in
`promises.cf` are not needed for this check. The fork-side all-or-nothing
loader (PR #41) and this check are independent: with the loader failing
closed, the file's keys are not loaded and the check refuses and reports
it, which is correct and louder.

Two findings from the implementation, both about the proof above. (1) The
Mac dev build (`3.29.0a.086d27749`) does not carry the per-entry loader
(`8f0076b81` is not an ancestor): an unresolved `$(...)` anywhere in `vars`
makes it install nothing at all, so the fail-open cannot be reproduced there
with a file. `tests/policy/sim-loader.cf` therefore installs
`data:variables.*` in the loader's place, from the same file, to emulate the
per-entry skip; the original policy was run against it first and did
process the service with its interlock skipped. The Linux CI legs build the
pinned fork and so also exercise the real per-entry skip with the literal
fixture (`tests/policy/fixtures/interlock-malformed.json`). (2) The check
needs `readjson` and `variablesmatching` to compose on the loader's
installed variables; they do on the dev build (checks 9-10 of
`tests/policy/run.sh`), so option 4 stays unneeded. The policy-tree digest
changes with this change (§13(b) option 3, §13(c)).

PR: https://github.com/frdminc/tendcf/pull/42

## 14. Review record

Gemini 4 Argon reviewed commit `a7b7c31` (2026-11-02; verdict "sound
with changes", 12 findings). Every claim was checked against the fork
at the pin, the policy and the schemas.

Several findings cite text this proposal does not contain:
`ledger.json`, `state/outbox/`, a TTL, a `publish` subcommand, a
"strict single-use" option, report-row fields `os`, `record_type` and
`host_id`, and a sentence in map §12 item 8 about "which schema carries
it ... and how the controller fetches it". The map has no such sentence;
its item 8 is only the detector question. Those findings were checked
for a real problem underneath. One line per finding:

1. *Amended.* Correct that `setpgid(0,0)` fails in the shell-`exec`s
   case, and that the `assert` is live under `--enable-debug`. Applied
   as fact 5 and item 1's process protocol: an `exec` prefix, cf-agent
   in its own group, signals forwarded, the wrapper's own deadline, one
   child at a time. Argon's "`(pid_to_kill != getpgid(0))`" condition
   is not in the source; the real one is `kill(-pid, 0) == 0`. Same
   effect.
2. *Applied.* Every forgery path is in the source. `tendcf_interlocks`
   runs `pre_action` commands unguarded under the first text. The guard
   moved to `bundlesequence` in `promises.cf`, `--no-augments` was
   added, and the guard is called an accident guard. Its failsafe
   detail is amended: the default failsafe command is
   `cf-agent -f failsafe.cf && cf-agent`, not an `update.cf` run.
3. *Amended.* The fail-open is real (fact 2). The proposed projector
   field breaks R21 and P-2, so it is option 1 of the new §13.
   Projector-unchanged alternatives are options 3-5. Marked for the
   operator, and picklist item 10.
4. *Applied.* The digest must cover `promises.cf` and refuse any other
   file in `inputs/`; see item 3's table. Argon's "cf-execd runs
   `inputs/update.cf`" is false (fact 14).
5. *Rejected.* It is about a ledger this design does not have. Here the
   approval is consumed at promotion, before launch, so a crash after
   actuation re-decides nothing (item 1, recovery).
6. *Amended.* The overlap is real (fact 13), though `exec_command`
   has no `-K`, contrary to the finding. `run` takes the lock
   non-blocking; `adopt` and `accept` wait with a bound.
7. *Amended.* There is no outbox. The real counterpart is unbounded
   JSONL growth, about 288 rows a day, whose retention is map §8's
   (item 3 table).
8. *Rejected as stated.* `report-row.schema.json` requires `device`,
   `recorded_at` and `release`, not `os`, `record_type` or `host_id`,
   and the proposal adds no approval-record field. A real conflict was
   found in its place: `release` and `converged_release` are signed
   release stamps that do not exist before Step 6 (item 3 table,
   picklist 12).
9. *Amended.* The quoted map sentence does not exist. The detector's
   row shape is already ruled: v5 R4 has the detector write report rows
   in the v5 reconciliation's §2.3(2) shape. How rows leave a Linux or
   macOS device is genuinely undefined (map §8 and
   [`linux-targets.md`](linux-targets.md) §4 item 3), and it belongs to
   the row writer, not to item 8. Added as picklist item 11.
10. *Amended.* The options it names (a "once per approval at install"
    option 3, TTL) are not this proposal's. The real dependency is that
    item 1 option 2 has no per-cycle process for item 3's `run` duties.
    Added to item 1's consequences.
11. *Amended.* There is no hostname check here, and host identity is a
    key by schema. The real gap is that no host has its identity key
    (`cf-key` makes RSA). Added to item 3's table and §9.
12. *Applied, amended.* Picklist items 10-12 were added (§13, row
    transport, pre-Step-6 row stamp). The "schema placement" sub-question
    is not real; see 9.
