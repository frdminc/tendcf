# S5: the report-only unit detector as a CFEngine custom promise (design note)

**Date:** 2026-11-02. **Author:** Claude Opus 5.5 (s5-design slice), on
`master` after S4. **Status: design, for two frontier reviews before any
code is written.** It records the operator's rulings R10-R13 (§1) and
settles what they leave to the design, except the items in §14, which it
lists for the operator. It changes no code, schema, policy or test.

Inputs: the read-only Rudder/CFEngine consult of 2026-11-02
(`~/.local/state/bigteam/adhoc-2026-11-02/tendcf-s5-consult-report.md`,
outside this repository; "the consult" below, its sections cited as
consult A1-D10), whose §C.8 is this note's outline;
[the v5 spec](schema-v5-dpkg-reconciliation-2026-11-02.md) (R1-R9, the
§2.3(2) row shape, the §3 detector contract, its §7 item 13);
[the `tendcf-validate` proposal](tendcf-validate-proposal-2026-11-03.md)
(its §0 facts, item 1's state layout, §13's interlock fail-open);
[the map](architecture-DEFINITIVE-v3.md) D45 and map §12;
[`bin/unit_classifier.py`](../../bin/unit_classifier.py),
[`schema/report-row.schema.json`](../../schema/report-row.schema.json),
[`deploy/linux/tendcf-install.sh`](../../deploy/linux/tendcf-install.sh) and
[`policy/tendcf_services.cf`](../../policy/tendcf_services.cf).

**How the CFEngine claims were checked.** The book (*Learning CFEngine*,
3.12) was searched first, in Basic Memory and with `book-kb query`. It covers
`ifelapsed` (ch. 28, ch. 46) and running with `--no-lock` (ch. 21). It has no
custom promise types, no promise modules and no `action_policy`: custom
promise types arrived in 3.17, after the book. Every claim about them below
was read in the fork source at the commit `overlay/fork.json` pins,
`b8abf28408b1b54e285d372a9bc5f2d850c960ad`, with `git show <pin>:<path>` in
`~/src/cfengine-core`. Line numbers are at that commit. §13 lists where this
corrects the consult, which read a different commit (its risk D9). §15 says
what was run and what was not.

## 1. Rulings

**From earlier documents, unchanged by S5:**

- **R4** (v5 spec §1): the detector lives in the CFEngine policy bundle as a
  report-only promise set, and writes report rows in the §2.3(2) shape.
- **D45** (map §15): tendcf-agent is Android-only. A Linux host runs
  CFEngine plus `tendcf-validate`, a command, not a daemon. D45 closed the
  tendcf-agent takeover that R4 had left open; the v5 spec's §7 item 13 and
  map §12 item 8 left open only whether another command takes the detector
  over. R10 below closes that.
- **What S5 does not change:** the §3 contract and its classifier; R3b
  (accidents only: ownership from the dpkg database, no hashes); R3d (a scan
  that cannot finish is `incomplete` and carries no counters, never a zero);
  report-only (nothing is removed, stopped or rewritten; the tombstone stays
  the only actuated removal path, v5 spec §3).

**djbclark, 2026-11-02 (Q46-Q49), relayed by lead `7c58015b`:**

| # | Ruling |
|---|---|
| R10 (Q46) | The mechanism is a **CFEngine custom promise type**, and R4 stands. A stdlib-only Python promise module in the bundle runs the shipped `bin/unit_classifier.py` unchanged, as a subprocess. Outcomes are audit-only, and the row is written to a path given as an attribute. The module uses its own protocol loop that advertises `action_policy` (the official library fails under `cf-agent -n`), runs under `python3 -I` with an empty environment, and keeps a total timeout. The `tendcf-validate` proposal's item 8 (a sibling command launched by the validator) is **not adopted**. |
| R11 (Q47) | The detector's input is the **verified goal file that `tendcf-validate` will write**. S5 merges with CI tests but does not run live until `tendcf-validate` exists. |
| R12 (Q48) | The scan runs as a **dedicated unprivileged user** (for example `tendcf-scan`), after a root-versus-unprivileged equivalence run that proves identical output. |
| R13 (Q49) | The fork's `ReadCMDBVars` is made **fail-closed on a bad CMDB entry**, in a separate slice, and `tendcf-validate` is still built as planned. |

**djbclark's later picks, 2026-11-02, from the validate proposal's
picklist (§10 there), relayed by the lead on 2026-11-06:**

| Pick | Ruling | Bearing on S5 |
|---|---|---|
| Q10 (picklist 10, the interlock fail-open) | **Both** option 3, the policy's cross-check of the loaded CMDB keys against the projection file, now; and option 5, an all-or-nothing CMDB loader in the fork, now built as tendcf PR #41 ("Pin the fork at the fail-closed CMDB loader (R13)", open on 2026-11-06) | Context only (below) |
| Q12 (picklist 12, the `release` column before Step 6) | `report-row` gains **`release_status`** and **`goal_sha256`**; **`release` may be empty only when `release_status` is `unsigned`** | Settles what S5's row carries before Step 6 (§6.2, §6.3). The schema change is not in the tree yet and is not S5's slice |

**R13 and Q10 are context here, not S5 work.** They address the interlock
fail-open of the validate proposal's §13 (its §0 fact 2: on the pinned fork
one bad entry drops one whole container, so a dropped `tendcf_interlock`
leaves every service ungated). The detector reads no CMDB data: its input is
the goal file (R11), not `host_specific.json`, so neither the fail-open nor
its two fixes change what the detector sees. The one interaction is
ordering. A run that the validator's launch guard refuses (validate proposal
item 1), or that Q10's policy cross-check sends to a refusing
`bundlesequence`, runs no tendcf bundle, the detector's included. DECIDED,
for the reviewers: the detector is not added to the refusing sequence. Such
a run is a frozen host whose refusal is already reported; a scan on it
would be read against a goal file that the run did not act on.

**How R10's "empty environment" is read.** The module process runs with no
inherited environment (§5.1). The classifier child gets an environment
built from nothing, holding `PATH` alone. A literally empty environment
breaks the unchanged classifier: `Env.__init__` takes its tool search path
from `os.environ.get("PATH", "")` (`bin/unit_classifier.py:76`), so with no
`PATH` every `shutil.which` fails, every command returns 127, and every scan
is `incomplete` (§5.2). DECIDED, for the reviewers to check: "empty" means
"nothing inherited", and `PATH` is set to a fixed constant.

## 2. Why a promise module

The consult's §A and §B carry the evidence; in short:

1. **Rudder** moves logic that outgrows promises into custom promise
   modules, and passes output that is bigger than classes through a file path
   given as a parameter, because the interface carries only classes and an
   outcome (consult A1.2, A1.3, with URLs there).
2. **CFEngine's custom promise interface** gives the agent the scheduling
   (`if`, `unless`, `ifelapsed`, `classes`) and gives the module one outcome
   per promise, `kept`, `repaired` or `not_kept`, plus result classes and log
   lines (§4). It runs under `cf-agent -n` if, and only if, the module
   advertises `action_policy` (§4.1).
3. **One implementation.** `bin/unit_classifier.py` is the contract, proven
   by its logic tests, its VM fixtures and two unprivileged reads of
   pastebin (v5 spec §3.6, §3.7). A policy rewrite (consult option 2) would
   be a second implementation; `commands:` plus the module protocol (consult
   option 1b) inherits this bundle's own ordering hazard
   (`policy/tendcf_services.cf:27-37`: every `classes:` before every
   `commands:` in each pass, and a class is never undefined).

The module adds only argument checks, a privilege drop, a bounded
subprocess, the outcome mapping and row assembly. It never interprets unit
state itself.

## 3. Promise type interface

```cf3
promise agent tendcf_unit_scan
{
      path => "$(sys.inputdir)/tendcf/modules/tendcf_unit_scan.py";
}

body action tendcf_unit_scan_every(minutes)
{
      ifelapsed => "$(minutes)";
}

bundle agent tendcf_unit_detector
{
  tendcf_unit_scan:
    systemd::
      "supervision"
        goal_file     => "<the verified goal file tendcf-validate publishes; §6.1>",
        classifier    => "$(sys.inputdir)/tendcf/bin/unit_classifier.py",
        scan_user     => "tendcf-scan",
        timeout       => "300",
        evidence_file => "$(sys.workdir)/state/tendcf-unit-scan/evidence.json",
        row_file      => "$(sys.workdir)/state/tendcf-unit-scan/row.json",
        device        => "<open: §14 O1>",
        release_status => "unsigned",       # Q12; before Step 6 (§6.3)
        action        => tendcf_unit_scan_every("60");
}
```

- **No `interpreter` line.** The agent then requires the module to be an
  executable file and runs the path alone (`libpromises/mod_custom.c:459-490`),
  so `-I` can sit in the shebang (`#!/usr/bin/python3 -I`). With an
  `interpreter`, the command is `"%s %s"` of interpreter and path, and the
  interpreter must itself be an executable file
  (`mod_custom.c:451-457`, `:487`), so there is nowhere to put a flag.
- **`systemd::`** is CFEngine's hard class for a host whose init is systemd
  (`libenv/sysinfo.c:1270-1299`). The classifier's own gate still decides
  `not-run` (v5 spec §3.1); the class only keeps the promise off launchd hosts.
- **The promiser** must be `supervision`, the one domain the contract scans
  (`bin/unit_classifier.py:835`).
- **Attributes** (all scalars; every path absolute):

| Attribute | Required | Meaning |
|---|---|---|
| `goal_file` | yes | The verified goal file (R11, §6.1) |
| `classifier` | yes | The installed classifier (§8) |
| `scan_user` | yes | The account the scan runs as (R12, §5.3); never uid 0 or gid 0 |
| `timeout` | no, default 300 | Total seconds for the whole scan, 30 to 1800 (§5.2) |
| `evidence_file` | yes | Where the full classifier output goes (§7) |
| `row_file` | no | Where the latest row goes; absent means no row (§6.3, §7) |
| `device` | with `row_file` | The row's `device` column, which the goal file does not carry (§6.2) |
| `release_status` | with `row_file` | The row's `release_status` (Q12). `unsigned` before Step 6; the other values are the Q12 schema slice's (§6.3) |
| `release` | only when `release_status` is not `unsigned` | The signed release stamp. Absent with `unsigned`: the module then writes the empty string itself (§6.3) |

- **Attributes the agent forwards and the module ignores.** A `body action`
  is expanded into the promise's own constraints (`DeRefCopyPromise`,
  `libpromises/promises.c:282-520`). The agent strips only `action`,
  `action_name`, `expireafter`, `log_level`, the `classes` body's attributes,
  `if`, `unless`, `depends_on`, `with` and `meta` before sending the rest
  (`mod_custom.c:721-745`). So `ifelapsed` from `tendcf_unit_scan_every`
  **reaches the module as an attribute**, as do `action_policy` and any other
  `body action` attribute. The module accepts the `body action` attribute
  names and ignores them, except `action_policy` (§4.1). Any other unknown
  attribute is `invalid`.

**Outcome mapping.** The module never returns `repaired`: it changes nothing
it promises about.

| Classifier result | Outcome | Log, enforce run | Log, warn run (§4.1) | Result classes |
|---|---|---|---|---|
| `complete`, all three counters 0 | `kept` | `verbose` summary | `verbose` summary | `tendcf_unit_scan_complete` |
| `complete`, any counter above 0 | `not_kept` | one `error` per non-zero counter, then up to 20 `warning` lines naming a non-clean unit and its rule | one `warning` per non-zero counter, then the same unit lines | `tendcf_unit_scan_complete`, plus `tendcf_unit_scan_extra`, `_two_writers`, `_unmet_absence` for each counter above 0 |
| `incomplete` | `not_kept` | one `error` per reason, up to 20, then a count of the rest | the same | `tendcf_unit_scan_incomplete` |
| `not-run` | `kept` | `verbose`, with the gate reason | `verbose` | `tendcf_unit_scan_not_run` |
| No usable result: classifier exit status not 0, timeout, output cap exceeded, stdout not one JSON object, a summary that breaks the §2.3(2) rules, goal file unreadable or not `schema_version` 5 | `not_kept` | `error` with the cause | `error` | `tendcf_unit_scan_failed` and `tendcf_unit_scan_incomplete` |

Three rules of the agent fix the log levels (`mod_custom.c`, at the pin):

1. **A `not_kept` in an enforce run needs at least one `error` (or
   `critical`) log line**, or the agent logs "Bug in promise module - Failed
   to log errors for not kept ..." at `critical` (`:1077-1097`). Findings are
   therefore `error` lines in an enforce run, not the consult's `warning`
   lines (§13 item C2).
2. **In a warn run a `not_kept` needs a `warning`, `error` or `critical`
   line** (`:1099-1108`).
3. **An `info` line in a warn run is reported as a module bug**
   (`:1039-1047`). `info` is CFEngine's level for a change made. The module
   never logs at `info`.

**`not_kept` means an audit finding here** (consult D7). A future consumer of
CFEngine's not-kept accounting, a canary check for example, must read the
`tendcf_unit_scan_*` classes, not the bare outcome.

**Result classes are bundle-scoped.** The agent defines them with
`EvalContextClassPutSoft(..., CONTEXT_SCOPE_BUNDLE, ...)`
(`mod_custom.c:1018-1027`), so they exist only inside
`tendcf_unit_detector`. Anything outside that bundle that needs the verdict
uses a `classes` body with `scope => "namespace"` on the promise, which the
agent handles itself. No consumer exists today; none is added in S5.

## 4. Protocol

The module speaks CFEngine's JSON promise-module protocol with its own loop,
about 100 lines of stdlib code. It does not use
`cfengine_module_library.py`, which hard-codes its header to
`json_based` (consult A2.3) and so fails every `cf-agent -n` run (§4.1).

1. **Start.** The agent writes `cf-agent <version> v1` and a blank line
   (`mod_custom.c:512-513`). The module answers
   `tendcf_unit_scan 1 v1 json_based action_policy` and a blank line. The
   agent reads flags from the fourth word on and sets `module->action_policy`
   on `action_policy` (`:534-567`).
2. **Requests** are one JSON object per line, ended by a blank line
   (`:366-380`); so are responses. `validate_promise` returns
   `valid` or `invalid`; `evaluate_promise` returns a result, optional
   `result_classes` and a `log` array; `terminate` returns `success`.
3. **Strict output, because the fork build asserts.** The Linux build is
   configured with `--enable-debug`
   (`.github/actions/build-fork/action.yml:54`), so the agent's `assert`s are
   live. A log entry without `level` or `message`, an unknown level
   (`mod_custom.c:131-136`), or a response line without its newline
   (`:201-203`) aborts cf-agent. The module emits only `error`, `warning`,
   `verbose` and `debug`, always as whole lines, and flushes after each
   blank line. Everything else the module or its child prints goes to
   stderr, never stdout: the agent leaves the module's stderr connected to
   its own (`mod_custom.c:492`, `capture_stderr` false; `libpromises/pipes_unix.c:313-400`).
4. **No interpretation of `log_level`.** The agent filters the module's lines
   against a promise's `log_level` itself (`mod_custom.c:139-148`).

### 4.1 `action_policy` and warn runs

- In a dry run (`-n`) or a simulate run, the agent appends
  `"action_policy": "warn"` to the attributes when the promise has none
  (`mod_custom.c:783-787`), and overrides a promise's own value with `warn`
  (`:747-751`).
- A module that did not advertise `action_policy` fails validation whenever
  the run is not a normal one or the promise's `action_policy` is `warn` or
  `nop`: "Not making changes to the system, but the custom promise module
  '%s' doesn't support action_policy" (`mod_custom.c:925-934`).
- **In a warn run the module runs the scan** (read-only, as `scan_user`),
  logs per §3's warn column, writes neither the evidence file nor the row,
  logs at `verbose` the paths it would have written, and returns `kept` or
  `not_kept` by the same mapping. `nop` is treated as `warn`.

The scan's one side effect, `systemctl show NAME` loading NAME in the manager
(`bin/unit_classifier.py:24-26`), is inherent in enumerating through the
manager and is a read for every purpose of the contract (v5 spec §3.6,
"Read-only"). It happens in warn runs too, as with Rudder's
`audit_from_command`, which runs in audit mode because it is read-only
(consult A1.5).

## 5. Execution

### 5.1 The module process

- **Started by the agent with `execv`, no shell:** the command string is
  split by `ArgSplitCommand` (`libpromises/pipes_unix.c:322`, `:385`), and
  the module inherits cf-agent's environment and uid. Under `tendcf-execd`
  that is root, with `LD_LIBRARY_PATH=/opt/tendcf/lib` from the unit
  (`deploy/linux/tendcf-install.sh:194`), or exported by the installer for
  `run-once` (`:36`).
- **Empty environment (R10).** The first statements of the module, before any
  import other than `os` and `sys`, re-execute it once:
  `os.execve("/usr/bin/python3", ["/usr/bin/python3", "-I", MODULE, "--clean"], {})`,
  where `MODULE` is the module's own resolved path. The re-exec is keyed on
  the `--clean` marker in `argv`, never on `os.environ` being empty: Python's
  C-locale coercion (PEP 538) puts `LC_CTYPE` into the environment of a
  process started with none, so an emptiness test would loop. The agent
  cannot pass arguments (no `interpreter`, and the path alone is the
  command), so the marker cannot be supplied from policy. The interpreter
  is started once under the inherited `LD_LIBRARY_PATH` before the re-exec.
  The installer's comment says that directory holds `librsync` and `libb2`
  (`tendcf-install.sh:31-36`), which `python3` does not load
  [INFERENCE: the directory's contents were not listed]. The alternative,
  a shebang of `#!/usr/bin/env -S -i /usr/bin/python3 -I`, avoids even that
  first start, but depends on the host's `env` supporting `-S`; it was not
  chosen.
- **`-I`** ignores every `PYTHON*` variable and the user site directory, and
  does not put the script's directory on `sys.path`
  ([Python docs, `-I`](https://docs.python.org/3/using/cmdline.html#cmdoption-I);
  not re-read for this note). With no environment left, it is belt and braces.
- **No timeout on the agent's side.** `mod_custom.c` has no `alarm`,
  `select`, `poll` or timeout anywhere (checked at the pin): the agent blocks
  in `getline` until the module answers. The module's own deadline (§5.2) is
  the only bound below cf-execd's `agent_expireafter` (default 120 minutes,
  validate proposal §0 fact 5).

### 5.2 The classifier subprocess

```python
subprocess.Popen(
    ["/usr/bin/python3", "-I", classifier, "--claims-json", claims_extract],
    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
    cwd="/",
    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    close_fds=True,
    start_new_session=True,
    user=scan_uid, group=scan_gid, extra_groups=[],
)
```

- **A subprocess, not an import** (R10): it can be killed on overrun, and
  its crash cannot take the protocol loop down.
- **Claims by argument, not by path.** The verified goal file sits in a root
  `0700` directory under the validate proposal's layout (item 1:
  `$(sys.workdir)/state/tendcf/`), which `scan_user` cannot open. The module
  (still root) reads the goal file, checks its trust (§6.1), and passes the
  classifier the subset `load_claims` reads (`bin/unit_classifier.py:183-202`):
  each domain's `coverage` and its `unit-writer`, `unit-package`, `service`
  and `supervisor` entries, without `device-trust`. Measured on pastebin's
  goal file (`deploy/linux/canary/goal-file.json`, 5,500 bytes): the compact
  extract is 4,588 bytes. Linux caps one argument at `MAX_ARG_STRLEN`, 32
  pages (128 KiB with 4 KiB pages) [kernel constant, not run here]; the module
  refuses an extract over 100 KiB as a failed scan (§3 last row). The
  classifier's existing `--claims-json` mode, which R8's pastebin probe used,
  needs no change. **Exposure:** a process's argument list is readable by
  every local user through `/proc/<pid>/cmdline` unless `/proc` is mounted
  with `hidepid`. The extract names units, packages and their claimed writers.
  Unit names and owners are already readable to any local user
  (`systemctl list-unit-files`, `dpkg-query -S`), so only the writer claims are
  added; the projection itself is installed `0600`
  (`tendcf-install.sh:151`). The alternative is a `0640 root:tendcf-scan`
  copy in a root-owned `0750` directory, which writes a file on every scan,
  warn runs included. DECIDED: argument, for the reviewers to check.
- **Environment:** `PATH` only (§1, "empty environment"). The classifier sets
  `LC_ALL`, `LANG`, `SYSTEMD_COLORS` and `SYSTEMD_PAGER` for its own children
  (`bin/unit_classifier.py:96-97`).
- **`start_new_session=True`** makes the classifier a session and group
  leader, so `os.killpg` reaches the `systemctl` and `dpkg-query` it runs.
- **Total timeout** (`timeout`, default 300 s). The classifier bounds each
  command at 120 s (`RUN_TIMEOUT`, `:64`) and not the scan. The module reads
  stdout and stderr with one `selectors` loop under one deadline. At the
  deadline, or when stdout passes 16 MiB or stderr 1 MiB, it sends `SIGTERM`
  to the group, waits 5 s, sends `SIGKILL`, reaps the child, and reports a
  failed scan. The same loop watches its own stdin: end of file means the
  agent is gone (for example after `systemctl stop tendcf-execd`, whose
  `KillMode=process` kills cf-execd alone, `tendcf-install.sh:197`), and the
  module kills the group and exits. A `SIGTERM` to the module does the same.
  The default of 300 s is a placeholder: the full-scan time on a unit-heavy
  host is unmeasured (v5 spec §3.6, "Not proven"), and S5e measures it on
  pastebin before choosing the value and `ifelapsed` (§9).
- **The classifier's exit status carries no verdict:** it exits 0 on an
  incomplete scan too (`bin/unit_classifier.py:892`). A non-zero exit means
  it crashed, and the scan is a failed one.

### 5.3 The unprivileged user (R12)

**Launch.** Python's own `user=`, `group=` and `extra_groups=[]` arguments
([subprocess docs](https://docs.python.org/3/library/subprocess.html)),
available since 3.9, not a `setuid` in a `preexec_fn`:

- The drop happens in the forked child before `exec`, in C, without running
  Python code between `fork` and `exec`. The docs warn against `preexec_fn`
  in a process that may have threads.
- `extra_groups=[]` is required. With `extra_groups=None`, the default,
  `Popen` makes no `setgroups` call (CPython 3.14.7 `subprocess.py:934-963`,
  read on this Mac), and the child keeps root's supplementary groups.
- The module resolves `scan_user` with `pwd.getpwnam` and uses that entry's
  primary gid. It refuses, as `invalid`, a user that does not exist or has
  uid 0 or gid 0. **It never falls back to root:** a missing user is a failed
  promise, which is visible, while a silent root scan would undo R12.
- Ids are dropped with `setregid` and `setreuid` on both real and effective
  ids, which also sets the saved ids, so the child cannot regain root
  [Linux `setreuid(2)` semantics, not run here]. The S5a tests assert
  `os.getresuid()`, `os.getresgid()` and `os.getgroups()` in a stub child
  (§10 T3).

**Creating the user** is the installer's job (S5b), in `cmd_install`, as root:

1. If `getent passwd tendcf-scan` finds nothing, run
   `useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin tendcf-scan`.
2. Then check, whether just created or pre-existing: uid not 0, primary
   group `tendcf-scan` with gid not 0, shell `/usr/sbin/nologin`, member of
   no other group. Any mismatch is `die`, with the field named. The installer
   never repairs an existing account it did not create.
3. `useradd` is in the `passwd` package, priority `required` in Debian
   [INFERENCE from Debian packaging, not checked on a host]; the
   `debian:13` CI job (`tests/deploy/bare-host-libs.sh`) proves it on a
   minimal image.

**Read access the scan needs as `tendcf-scan`:** the classifier file and the
directories above it (the installed tree is `go-w`, not `go-r`:
`tendcf-install.sh:78-79`, `:96-97`, `:120-122`); the manager over D-Bus for
`systemctl show`, `cat` and `list-*`; the dpkg database; `lstat`, `readlink`
and listing in the unit directories. R8's pastebin probe ran unprivileged and
was `complete` (v5 spec §3.6).

### 5.4 The equivalence run (R12)

**What can differ.** Root and `tendcf-scan` see different things only where a
permission check differs: a unit file, drop-in directory or link that is not
world-readable, or a `systemctl cat` that reads a file the user cannot.
Every one of those paths in the classifier turns into a problem, and so into
`incomplete`, never into a different count: a failed `systemctl cat` is a
unit problem (`bin/unit_classifier.py:704-706`), a drop-in directory that
cannot be listed is caught (`:633-634`), and a probe that raises is caught
(`:739-741`). So the expected failure shape is "unprivileged `incomplete`,
root `complete`". That is read from the code; the runs below prove it.

**The comparison.** One function, in the module, launches the classifier;
the equivalence check calls that same function twice, back to back, on the
same claims: once with the drop and once without (root). It compares the two
**complete JSON outputs** (`summary`, `units` with every artifact, `conflicts`,
`incomplete`), parsed and re-serialised with sorted keys, for exact equality.
It is a mode of the module, `tendcf_unit_scan.py --equivalence GOAL_FILE`,
read-only, root-only, printing the first differing unit on a mismatch and
exiting 1. A mode of the same file means the check exercises the production
launch code, not a copy. On a live host the unit set can change between the
two scans; on a mismatch the pair is run once more, and only a mismatch that
repeats counts. In CI the fixtures hold the host still, so one pair decides.

**Where it runs:**

1. **CI, every ubuntu VM job** (`TENDCF_TEST_SYSTEMD=1`, root). The workflow
   creates `tendcf-scan` with the installer's own command. Every fixture in
   `tests/unit_classifier/test_fixtures.py` gains an equivalence assertion:
   after the root run it already makes, it runs the classifier through the
   module's launch function as `tendcf-scan` and requires identical output.
   One new fixture makes a drop-in directory `0700 root` and asserts the
   **known** divergence: root `complete`, `tendcf-scan` `incomplete`, naming
   that directory. The other fixtures must match exactly; that they create
   nothing unreadable to other users is what this check proves, not assumes.
2. **pastebin, once, before enablement** (S5e): `--equivalence` on the
   verified goal file, read-only, by the operator or with his leave (R8 allowed
   only one probe before S4, so this is a new read). Its full output is kept
   in the run's state directory.

**If they differ:**

- `tendcf-scan` `incomplete` where root is `complete`: a host permission
  finding, named by the output. S5e does not enable the detector on that host
  until the operator rules: make the path world-readable (it is unit
  configuration, normally `0644`), or accept `incomplete` there. Root is
  never chosen by the module or the installer; R12 holds.
- Two different **complete** results, or `tendcf-scan` complete where root is
  not: a classifier defect. Live enablement stops, and the fix lands with a
  fixture that reproduces it.

## 6. Inputs and row assembly

### 6.1 The goal file (R11)

- **Path:** the verified goal file `tendcf-validate` publishes. The
  validate proposal (item 1, a proposal, not ruled) puts it at
  `$(sys.workdir)/state/tendcf/current/goal.json`, with `current` a symlink
  to `gen/<sha256>/` in a root `0700` directory. The path is the `goal_file`
  attribute, so the policy names it once `tendcf-validate` is built; the
  module has no default.
- **What the module trusts.** `tendcf-validate`'s verification. The module
  re-checks only what it needs to read the file safely: it resolves the path,
  requires a regular file whose every directory, from `/` down, is owned by
  root and not group- or world-writable, reads at most 5 MiB, parses JSON, and
  requires `schema_version` 5. Any other version is a failed scan
  ("goal file schema_version N, detector reads 5"), never a guess: the same
  fail-closed version dispatch the map asks of every reader (map §9.6).
- **Absent file.** A failed scan (`not_kept`, `error`). Under the launch
  guard the validate proposal recommends, a run without a verified goal file
  runs no tendcf bundle at all, so this is a fault and not a normal state.

### 6.2 Where each row column comes from

The consult said the row's extra fields all come from the goal file (consult
A3.3, C.2 step 4). **The goal file holds none of them.** Its top level is
`schema_version`, `host` and `domains` only (`schema/goal-file.schema.json`,
`required` and `properties`); `host` is a public key (`ed25519:...`), not
the inventory name a row's `device` is (`common.schema.json` `host_name`);
there is no release field; and each domain has one `coverage` value, not
counts.

| Column | Source | State |
|---|---|---|
| `row_type`, `domain` | Classifier summary (`domain_coverage`, `supervision`; `bin/unit_classifier.py:835`) | settled |
| `extra_scan`, `extra_entries`, `two_writers`, `unmet_absence` | Classifier summary, copied, never computed. A failed scan writes `extra_scan: incomplete` with no counters | settled |
| `recorded_at` | The module's clock when the classifier exits, RFC 3339 with offset, seconds | settled |
| `device` | The `device` attribute | **open, §14 O1** |
| `release_status` | The `release_status` attribute: `unsigned` before Step 6 (Q12) | settled by Q12; the column awaits the schema slice |
| `release` | Empty string when `release_status` is `unsigned` (Q12); otherwise the `release` attribute | settled by Q12 |
| `goal_sha256` | SHA-256 of the goal-file bytes the module read and passed on to the classifier (§6.1) | settled by Q12; spelling is the schema slice's |
| `managed`, `not_yet_migrated`, `deliberately_unmanaged` | Not derivable from the goal file; a proposed rule is in §14 O3 | **open, §14 O3** |

### 6.3 What S5 writes before Step 6

There is no signed release before Step 6, and today's `release` column is
defined as one (`common.schema.json` `release_stamp`: "the signed release
that produced this row", a non-empty pattern). **Q12 settles this:** the row
gains `release_status` and `goal_sha256`, and `release` may be empty only
when `release_status` is `unsigned`. Before Step 6 the detector's row
therefore carries:

- `release_status: "unsigned"`, from the policy;
- `release: ""`, written by the module, never taken from policy. The policy
  leaves `release` out under `unsigned` and the module refuses the promise
  (`invalid`) if it is given. That keeps the empty value out of CFEngine
  attribute handling, and keeps a stale stamp from being typed in;
- `goal_sha256`: the SHA-256 of the exact bytes of the verified goal file
  that the module read and extracted the claims from. These are the
  canonical bytes `tendcf-validate` stores (validate proposal item 1:
  `gen/<sha256-of-goal>/goal.json`), so the row names the goal file its
  counts were judged against. The module hashes once and uses the same
  buffer for the extract, so the two cannot disagree.

Q12 is a change to `report-row`, answering validate picklist 12, which asked
it for the `device_convergence` row. The detector follows the same rule, so
its row and `tendcf-validate`'s stamp one run the same way. Which row kinds
carry the two new columns is the schema slice's to write; this note assumes
`domain_coverage` does. The Q12 schema change is not in the tree (checked on
`origin/master` at `be20550`, 2026-11-06: no `release_status` or
`goal_sha256` in `schema/` or `docs/`). The module's row writer depends on
it, and S5d waits for it (§12).

**S5 still writes no row until O1 and O3 are ruled** (§14): `device` and the
three coverage counters have no source. The policy omits `row_file`, and the
module requires `device` and `release_status` whenever `row_file` is given.
Until then the scan's result reaches the operator through:

- the result classes and log lines (§3), which cf-execd keeps in
  `$(sys.workdir)/outputs/` (validate proposal §0 fact 4);
- the evidence file (§7), whose `summary` is exactly the row fragment the
  classifier produced, and which records `goal_sha256` too.

When the rulings land, enabling the row is a policy change (adding
`row_file`, `device` and `release_status`) plus, for O3, the counter rule in
the module.

**Row checks on the host.** No JSON Schema library is assumed on the host
[INFERENCE: not checked; the module is stdlib-only by R10]. The module checks
by code what the schema requires of a `domain_coverage` row: the required
keys; integers at least 0; `extra_scan` in its enum; the three counters
present exactly when `complete`; no other keys; `device` matching
`^[a-z0-9][a-z0-9._-]*$` within 64 characters; `release` empty exactly when
`release_status` is `unsigned`, and otherwise matching the `release_stamp`
pattern. The checks follow the schema as the Q12 slice lands it. CI validates
every row the tests produce against `schema/report-row.schema.json` itself
(§10).

## 7. Outputs

- **Directory:** `$(sys.workdir)/state/tendcf-unit-scan/`, root `0700`,
  created by the installer (S5b), not by the module: in a warn run the module
  may create nothing, and an enforce run should not differ from it in what
  exists. It is a directory of its own, not `tendcf-validate`'s state
  directory, so that each directory keeps one writer. The module refuses the
  promise (`invalid`) if the directory is missing, is a symlink, is not owned
  by root or is not mode `0700`.
- **Evidence file** (`evidence_file`): the classifier's full JSON output,
  plus the module's own record of the run: `recorded_at`, duration, the
  `sha256` of the classifier file and of the goal file, `scan_user`, and the
  failure cause for a failed scan. Mode `0600`, root. This is the "detector's
  log line" the v5 spec §3.4 asks for, kept as a file because one scan of
  pastebin judges 251 units (v5 spec §3.7).
- **Row file** (`row_file`, once enabled): one JSON object, the latest row.
- **Atomic write:** `mkstemp` in the same directory, mode `0600`, write,
  `fsync`, `rename` over the target, `fsync` of the directory. A reader sees
  the old file or the new one, never a partial one.
- **Retention:** the latest of each, overwritten by each scan. Nothing
  appends.
- **JSONL capture: open.** The consult's C.9.2 (latest file only, or the D18
  JSONL capture too, with its path, rotation and single-writer rule; map §8
  and `linux-targets.md` §4 item 3) is **not ruled**. S5 writes the latest
  file only and invents no JSONL path (§14 O5).
- **Two runs at once.** cf-execd starts a run on schedule whether or not the
  last one has ended (validate proposal §0 fact 13). The promise lock makes a
  second scan within `ifelapsed` a skip, but a `run-once` (`-K`) beside a
  scheduled run can scan twice at once. Each run writes whole files by
  `rename`, so the last writer wins and no file is torn.

## 8. Integrity

- **Shipped files.**
  - `policy/modules/tendcf_unit_scan.py`, mode `0755` in git;
  - `policy/tendcf_unit_detector.cf`, the bundle of §3;
  - the classifier, staged by the installer from `bin/unit_classifier.py` into
    `inputs/tendcf/bin/unit_classifier.py` inside `place_policy`'s staging
    directory, before the atomic swap (`tendcf-install.sh:116-124`). One
    source file in git, no copy to drift. A symlink in `policy/` would be
    copied as a link by `cp -R` and dangle.
- `place_policy` makes the whole staged tree `root:root` and `go-w`, and
  `cp -R` keeps the module's execute bit under the script's `umask 022`.
- **Run-time checks, at `validate_promise`:** the module and the classifier
  are each `lstat`ed and must be regular files, owned by root, not group- or
  world-writable, not symlinks, with the same check on every directory up to
  `/`. These are Rudder's checks for code that root runs (consult A1.7). The
  classifier is never run from a repository checkout.
- **Not settled here:**
  - the policy-tree digest, which covers these files once someone checks it
    (validate proposal item 3; `change-process.md` §3);
  - `/usr/bin/python3`, a distribution file, whose trust is map §12 item 4's
    open DC-11 question for `tendcf-validate`'s interpreter too. The detector
    uses the same interpreter and takes whatever that ruling says.

## 9. Scheduling

- **Once per agent run at most.** Custom promise sections run at the end of
  each of the agent's passes, after the built-in types
  (`cf-agent/agent_operations.c:210-235`, normal order). The agent's promise
  lock cache records a promise's digest on the first pass and skips it on
  later passes of the same run, **with or without `-K`**: the cache check
  comes before the ignore-locks check (`libpromises/locks.c:856-868`). So a
  `run-once` (`-K`) scans once, not three times.
- **`ifelapsed`** spaces scans across runs. Under `-K` it is ignored, by
  design, and a `-K` run does not reset the window (§15.1).
- **The module process starts on every run, scan or not.** The agent starts
  the module (`mod_custom.c:1282`) before it takes the promise lock
  (`:1322`), so a run inside `ifelapsed` still starts the module, and its
  re-exec, and sends it only `terminate`. The module therefore does nothing
  at start but the re-exec and the header: no goal-file read, no `pwd`
  lookup, no directory check before `validate_promise`.
- **Placement:** the bundle runs after `tendcf_services` in `bundlesequence`,
  so a run's scan sees the units after that run's changes.
- **Cost:** a scan holds cf-agent until it ends, because the agent waits on the
  module (§5.1). The cost of one scan on pastebin is unmeasured. S5e
  measures it, then sets `timeout` well below the validator wrapper's
  deadline (validate proposal item 1) and `ifelapsed` to bound the manager
  load of `systemctl show` (consult D5).
- **Not live in S5's merge (R11):** the bundle file ships, but
  `promises.cf`'s `bundlesequence` does not name it until S5e.

## 10. Tests

Repository convention: `python3 -m unittest`, as `linux.yml` runs
`tests/unit_classifier/`. Locally through `~/ops/site-private/bin/bg`, one
suite at a time.

| # | Test | Where | Root |
|---|---|---|---|
| T1 | `tests/unit_classifier/` unchanged, and passing unchanged | CI, as today | as today |
| T2 | **Protocol, canned stdin** (`tests/unit_scan/test_protocol.py`): the header carries `json_based action_policy`; `validate_promise` refuses a wrong promiser, an unknown attribute, a relative path, a missing or uid-0 `scan_user`, a group-writable, symlinked or non-root classifier, a state directory that is not root `0700`, and accepts the forwarded `ifelapsed` and `action_policy`; every response line is newline-terminated JSON with only the four levels of §4 | any OS | no |
| T3 | **Outcome mapping and launch** (`test_mapping.py`), with a stub classifier: complete with zeros, complete with each counter, incomplete, not-run, exit status 1, a sleep past `timeout` (the group is killed: a grandchild's pid is gone), stdout past the cap, garbage stdout, empty stdout. Asserts outcome, classes, log levels per mode (an `error` for every enforce `not_kept`, never `info`, never `repaired`), that a warn run writes nothing, the atomic write, the row checks of §6.3, and that the evidence `summary` equals the stub's. As root on the VM: the stub child reports `getresuid`, `getresgid` and `getgroups` of `tendcf-scan` with no supplementary groups, and an environment of `PATH` alone | any OS; drop asserts on VM | drop asserts only |
| T4 | **Real cf-agent** (`tests/policy/run.sh` check 8, the stub classifier in test policy): `-K` and `-n`. Asserts the classes (through `reports:`), the evidence file after `-K` and its absence after `-n`, no "doesn't support action_policy", no "Bug in promise module" line, never "repaired", and the stub invoked once per `-K` run (lock cache); a second run without `-K` inside `ifelapsed` does not invoke it | every CI image; the Mac dev build | no |
| T5 | **End to end on systemd** (`TENDCF_TEST_SYSTEMD=1`): installer creates `tendcf-scan` and the state directory; `tendcf-install.sh run-once` runs the real classifier through cf-agent with `LD_LIBRARY_PATH=/opt/tendcf/lib` inherited; the evidence `summary` equals a direct `unit_classifier.py --quiet` run on the same claims; once the Q12 schema lands, a test row built with a fixture `device` and `release_status: unsigned` validates against `report-row.schema.json`, carries `release: ""`, and its `goal_sha256` equals `sha256sum` of the goal file | ubuntu VM jobs | yes |
| T6 | **Equivalence** (§5.4): every fixture compared root against `tendcf-scan`, plus the `0700` drop-in fixture asserting the known divergence | ubuntu VM jobs | yes |
| T7 | **Installer** (`tests/deploy/linux-install.sh`, `bare-host-libs.sh`): user created once and idempotent; a pre-existing `tendcf-scan` with uid 0, a login shell or an extra group is refused; the classifier is staged inside the swapped tree, `0644`, root; the module `0755` | ubuntu VMs, `debian:13` | yes |
| T8 | **Mutation check**: one mutant at a time, each under `timeout`, running only T2-T4's new tests: (a) counters above 0 map to `kept`; (b) header without `action_policy`; (c) a warn run writes the evidence file; (d) `env` passed through; (e) `extra_groups` omitted; (f) the total timeout not enforced; (g) `info` instead of `error` for findings. Each must turn at least one test red | any OS (e: VM) | (e) only |

T4's `-n` run is the guard against the library trap (consult D1): a module
that does not advertise `action_policy` passes every enforce run and fails
every dry run.

## 11. Platforms

- **Linux, systemd and dpkg:** in scope. The classifier's gate gives
  `not-run` unless `supervisor` is `systemd` and `supervision` is
  `comprehensive` (v5 spec §3.1), and `incomplete` when the dpkg database
  answers no owner for dpkg's own files (§3.1, K7).
- **NixOS:** the policy promise is not deployed there in S5. A systemd host
  without dpkg can only ever be `incomplete` (v5 spec §7 item 11), and the
  NixOS module installs no policy today (validate proposal §0 fact 9).
- **macOS (launchd):** out of scope. The v5 contract is systemd plus dpkg;
  the `systemd::` guard keeps the promise off a Mac. A launchd extra-scan
  would be a different contract held to the same row shape.
- **Android:** out of scope for this contract, not for CFEngine. The map keeps
  CFEngine on Android beside tendcf-agent (map §12; consult A3.7 corrects the
  brief that said otherwise), but Android supervises with `termux`, so this
  gate gives `not-run`. An Android detector is a termux-services contract,
  held only to the row schema.

## 12. Slices

All in worktrees, on Sonnet 5.5 `high` or better, each PR with a
cross-model frontier review (`AGENTS.md`, standing rule).

| Slice | Content | Depends on |
|---|---|---|
| S5a | `policy/modules/tendcf_unit_scan.py`: protocol loop, re-exec, validation, launch with the drop, deadline and caps, outcome mapping, evidence and row writers, `--equivalence` mode. Tests T2, T3 (no-root part) and T8 | this note reviewed |
| S5b | `policy/tendcf_unit_detector.cf` (§3, `row_file` omitted); installer: `tendcf-scan` creation and checks, classifier staging, the state directory; `promises.cf` `inputs` gains the file, `bundlesequence` unchanged. Tests T4 and T7 | S5a |
| S5c | VM jobs: T3's drop asserts, T5, T6 (equivalence on every fixture, the `0700` fixture) in `linux.yml` | S5b |
| S5d | Row enablement: the counter rule and the `device` source as ruled; the `release_status`, `release` and `goal_sha256` columns per Q12; policy gains `row_file`, `device`, `release_status` | O1 and O3 ruled (§14); the Q12 schema change merged |
| S5e | Live on pastebin: `goal_file` set to `tendcf-validate`'s path; pastebin's equivalence run (§5.4); scan time measured; `timeout` and `ifelapsed` set; the bundle added to `bundlesequence`; deployed with the installer and checked | `tendcf-validate` built (R11); R12's pastebin run; operator approval of the deploy |

S5a-S5c merge without changing live behaviour on any host (R11). S5d can land
before or after S5e; until it does, the live detector writes no row (§6.3).

## 13. Corrections to the consult, with source

Every line reference is at the fork pin unless stated.

1. **C1, risk D9 resolved: the cited `mod_custom.c` lines hold.**
   `git diff --stat d5052b786 b8abf284 -- libpromises/mod_custom.c` is empty:
   the file is identical at the commit the consult read and at the pin. Its
   `:925-934`, `:783-786` and `:451-492` are correct as cited.
2. **C2, log level for findings.** The consult maps findings to `not_kept`
   "with a `warning` log per counter" (C.2 step 2). In an enforce run that
   makes the agent log a `critical` "Bug in promise module - Failed to log
   errors for not kept" (`mod_custom.c:1090-1097`). Findings log at `error`
   in enforce runs, `warning` in warn runs (§3).
3. **C3, `info` in warn runs** is flagged as a module bug
   (`mod_custom.c:1039-1047`). The consult does not mention it; the module
   never logs at `info`.
4. **C4, attribute allowlist.** The consult's `validate_promise` allows "only
   the four path attributes (plus `action_policy`)" (C.2), while its own
   example uses `action => if_elapsed("60")` (C.1). The action body's
   `ifelapsed` reaches the module as an attribute
   (`libpromises/promises.c:282-520` appends body attributes;
   `mod_custom.c:721-745` strips only `action`, `action_name`, `expireafter`
   and `log_level` of them), so that allowlist would make the consult's own
   promise `invalid` (§3).
5. **C5, result classes are bundle-scoped** (`mod_custom.c:1026`,
   `CONTEXT_SCOPE_BUNDLE`), not global (§3).
6. **C6, how the module is started:** `execv` after `ArgSplitCommand`, no
   shell (`libpromises/pipes_unix.c:322`, `:385`, at `cf_popen_full_duplex`),
   with stderr not captured (`mod_custom.c:492`). The consult's "no privilege
   drop in that file" holds: neither `setuid` nor any timeout primitive
   appears in `mod_custom.c`.
7. **C7, evaluation order** is in `cf-agent/agent_operations.c:210-235` in
   the fork, not `cf-agent.c`; normal order only (top-down order evaluates
   promises in source order, `:260-290`).
8. **C8, one scan per run even under `-K`** (`libpromises/locks.c:856-868`).
   The consult did not address passes; without the lock cache a `-K` run
   would scan up to three times.
9. **C9, row columns.** The goal file holds no `device`, `release` or
   coverage counts (§6.2). The consult's "all from the goal file" (A3.3, C.2
   step 4) does not hold.
10. **C10, empty environment.** The classifier takes `PATH` from its
    environment (`bin/unit_classifier.py:76`), so the child needs `PATH`
    (§1, §5.2). The consult's environment for the child (`PATH` and
    `LANG=C.UTF-8`) works; R10's literal "empty" does not.
11. **C11, claims delivery.** The consult passes the goal file by path
    (`--claims`); the scan user cannot read the validator's root `0700`
    state directory, so the module passes an extract with `--claims-json`
    (§5.2).
12. **C12, `user=` alone keeps root's groups.** The consult names
    `preexec_fn`/`user=`; `extra_groups=[]` is required as well
    (`subprocess.py:934-963`), and `preexec_fn` is not used (§5.3).
13. **C13, the fork build asserts.** `--enable-debug` makes a malformed log
    entry or an unterminated response line abort cf-agent
    (`mod_custom.c:131-136`, `:201-203`); the consult's risk list does not
    include it (§4 item 3).
14. **C14, consult C.4's classifier copy under `policy/bin/`** would be a
    second copy in git. The installer stages the one file instead (§8).
15. **C15, the module starts even when `ifelapsed` skips the promise**
    (`mod_custom.c:1282` before `:1322`; observed in §15.1). The consult's
    C.1 leaves `ifelapsed` to the agent, which is right for the scan, but
    the module's start-up runs on every agent run, so it must stay cheap (§9).

## 14. Open items

For the operator unless marked:

1. **O1, `device`.** The row's `device` is a Site Model inventory name
   (`host_name`); the goal file carries the host's key, not its name. Options:
   (a) the installer records the inventory name (a `--device NAME` argument)
   in the policy it writes; (b) `tendcf-validate` publishes it beside the goal
   file; (c) CFEngine's `$(sys.uqhost)`, which is the OS hostname and may differ
   from the inventory name. Recommendation: (b), one source for both row kinds,
   if `tendcf-validate`'s design can carry it; otherwise (a). Not (c).
2. **O2, `release` before Step 6: ruled by Q12** (§1, §6.3). Pre-Step-6
   rows carry `release_status: unsigned`, `release: ""` and `goal_sha256`.
   What remains is the schema slice that adds the two columns, not S5's.
3. **O3, the coverage counters.** `managed`, `not_yet_migrated` and
   `deliberately_unmanaged` are required on every `domain_coverage` row, and
   nothing defines them for a goal-file domain, which has one `coverage` value.
   (The example row in `examples/report-rows.yml`, with all three non-zero
   in one domain, predates the one-value coverage enum.) Proposed: on the
   `supervision` row, `managed` is the number of `service` entries in that
   domain of the verified goal file, present and tombstoned; `not_yet_migrated`
   and `deliberately_unmanaged` are 0 when the domain is `comprehensive`. For a
   `not-run` row of a domain that is not comprehensive, the backlog cannot be
   counted, so no row is written for it. Needs a ruling: it fixes what the
   build-order metric means.
4. **O4, the goal-file path**, from `tendcf-validate`'s design (R11). Not an
   operator question: S5e takes whatever that build publishes.
5. **O5, JSONL** (consult C.9.2), not ruled. Default: the latest-row file
   only (§7).
6. **O6, for the reviewers:** the readings DECIDED in this note: "empty
   environment" with a fixed `PATH` (§1); claims by argument (§5.2); findings as
   `not_kept` (§3); the module's own state directory (§7); the detector kept
   out of a refusing `bundlesequence` (§1); `release` written as `""` by the
   module, never from policy, under `unsigned` (§6.3).

**Documents this note does not amend.** Map §12 item 8, the v5 spec's §6 S5
row and §7 item 13, and the validate proposal's picklist item 8 still read
as open. R10 closes them; amending them is left to the lead, to keep this
slice to one new document.

## 15. What was run, and what was not

**Run or read for this note (2026-11-02 and 2026-11-06):**

- the fork source at the pin, read with `git show` (`mod_custom.c`,
  `locks.c`, `promises.c`, `attributes.c`, `pipes_unix.c`, `sysinfo.c`,
  `cf-agent/agent_operations.c`), and `git diff --stat` against `d5052b786`;
- the book: four Basic Memory searches (`bm tool search --project books`, on
  dry runs and `action_policy`, on `ifelapsed` and locks, on promise locking,
  on running as root or as another user) and `book-kb query` for the exact
  terms. The book has `ifelapsed` (ch. 28, ch. 46) and `--no-lock`, which it
  glosses as "Ignore locking constraints during execution, which in practice
  means 'always execute all promises'" (ch. 21). It has no match for custom
  promises, promise modules, `action_policy`, `exec_owner` or `--dry-run`:
  those postdate 3.12 or fall outside it, so every claim about them rests on
  the source and the probe below. The book's gloss of `-K` is about locks
  across runs; within one run the lock cache still evaluates a promise once
  (§9; probe below);
- the size of pastebin's goal file and of its claims extract (a throwaway
  script over the checked-in file);
- CPython 3.14.7's `subprocess.py` on this Mac, for `extra_groups`;
- the probe of §15.1.

**Not run:** no module exists, so no test in §10 has run. Not checked on a
host: Python's `-I` and PEP 538 behaviour as described, `setreuid` saved-id
semantics, `MAX_ARG_STRLEN`, `useradd` availability on Debian 13, the
contents of `/opt/tendcf/lib`, the python3 versions on the target images,
whether cf-agent forwards an empty-string attribute (avoided by §6.3), and
the fork's Linux build: the probe ran the Mac dev build only.

### 15.1 A probe with a real cf-agent

**What ran.** The Mac dev build at `~/opt/cfengine-dev/bin`, CFEngine
3.29.0a.086d27749. That commit differs from the pin only in
`libpromises/pipes_unix.c` among `mod_custom.c`, `locks.c`, `promises.c`,
`agent_operations.c` and `pipes_unix.c` (`git diff --stat`). The pin's
change there is in `GenericCreatePipeAndFork`, which the module launch also
goes through (`cf_popen_full_duplex` calls it via `CreatePipesAndFork`,
`pipes_unix.c:296-325`): the child leads its own process group, and the
timeout clock starts, only while a command timeout is armed
(`:242-273`). At the pin, `SetTimeOut` is called only from
`cf-agent/verify_exec.c:308` (a `commands:` promise's `contain` timeout),
`cf-agent/nfs.c` and `cf-monitord/history.c`, and nowhere on the
custom-promise path (`git grep` at the pin). So the module starts in
cf-agent's process group at the pin, as on the dev build, provided each of
those callers disarms afterwards (`ClearTimeOut`; not traced). Each run used a fresh scratch
work directory in `tests/policy/run.sh`'s pattern
(`CFENGINE_TEST_OVERRIDE_WORKDIR`, `ppkeys` `0700` with a `cf-key` pair,
`bin/` linked to the `cf-*` tools), unprivileged, through
`~/ops/site-private/bin/bg`. The promise module was a throwaway probe under
`/tmp`, shebang `#!/usr/bin/python3 -I`, no `interpreter` line, that recorded
every request and answered by a mode file. The policy declared
`promise agent probe`, one promise with an attribute `goal_file` and
`action => probe_elapsed("60")` (a `body action` with `ifelapsed`), and a
`reports:` promise on the result class. Nothing of it is committed.

**What it showed** (agent exit status 0 in every run):

| Run | Observed |
|---|---|
| Header with `json_based action_policy`, `-K` | The agent sent `cf-agent 3.29.0a.086d27749 v1`. One `validate_promise`, one `evaluate_promise` and one `terminate` over the whole run: **one evaluation per `-K` run**, although the agent makes three passes. The result class was set (`R:` line) |
| Same, attributes as received | `{"goal_file": "/x/goal.json", "ifelapsed": "60"}`: **the action body's `ifelapsed` reaches the module**; `action` itself does not. `log_level` arrived as a request field (`notice`), not as an attribute |
| Header with `json_based` only, `-K` | Validated and evaluated normally: without `-n` the flag is not needed |
| Header with `json_based` only, `-n -K` | `error: Not making changes to the system, but the custom promise module '…' doesn't support action_policy`; no `validate_promise` or `evaluate_promise` was sent. **The library trap, reproduced** (consult D1) |
| Header with `action_policy`, `-n -K` | Both requests carried `"action_policy": "warn"`, added by the agent to a promise that sets none |
| `not_kept` with a `warning` line only, `-K` | `CRITICAL: Bug in promise module - Failed to log errors for not kept probe promise …`. **Correction C2, reproduced** |
| `not_kept` with an `error` line, `-K` | The error line only, no `critical` |
| `not_kept` with a `warning` line, `-n -K` | The warning line only, no `critical`: a warning suffices in a warn run |
| `kept` with an `info` line, `-n -K` | `CRITICAL: Bug in promise module - 'info:' log messages reported … while making changes on the system disabled`. **Correction C3, reproduced** |
| Module environment | The module inherited the agent's whole environment (the probe recorded its keys), which is why §5.1 re-executes it with none |
| `bin/unit_classifier.py`'s `Env()` under `env -i` | `Env.path` is `''` and `which` finds nothing; with `PATH=/usr/bin:/bin` it finds `/bin/ls`. **Correction C10, reproduced.** (On this Mac `/usr/bin/python3` is Apple's shim, which adds variables such as `SDKROOT` to an empty environment; that is macOS-only and not a Linux observation) |

**Across runs, in one work directory** (a second probe, same pattern, four
agent runs back to back with `ifelapsed` 60 minutes):

| Run | Module started | `evaluate_promise` sent |
|---|---|---|
| 1, no `-K` | yes | yes |
| 2, no `-K`, inside the window | yes | **no**: the lock held |
| 3, `-K` | yes | yes: `-K` ignores the lock |
| 4, no `-K` | yes | **no**: the window from run 1 still holds; run 3 did not reset it |

So `ifelapsed` from a `body action` spaces scans across runs as §9 says, and
the module is started even on a run that skips it (§9).
